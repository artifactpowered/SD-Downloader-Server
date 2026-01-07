# Standard
import os  
import time
import csv
import json
import uuid
import threading
import base64
import asyncio
import zipfile
import io
import logging
import re
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler

# Third-party
import ocrmypdf
from flask import Flask, request, jsonify, render_template, send_file, redirect, url_for
from flask_cors import CORS
from apscheduler.schedulers.background import BackgroundScheduler
from PyPDF2 import PdfMerger
from PIL import Image
from playwright.sync_api import sync_playwright
from playwright.async_api import async_playwright
from stem import Signal
from stem.control import Controller
from io import BytesIO
from functools import wraps


# -----------------------------------------------------------------------------------------------------------------------------
# SD-Downloader Backend Server 
# Receives cookies and URL from the Chrome extension, captures the HAR file or reconstructs the PDF document.
# © 2025 artifact SAS
# -----------------------------------------------------------------------------------------------------------------------------



BASE_PATH = "/srv/www/sdd/"
RECONSTRUCTION_PAGE_LIMIT = 200

# Logging Set-Up
LOG_DIR = os.path.join(BASE_PATH, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

log_formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
log_file = os.path.join(LOG_DIR, "app.log")

file_handler = RotatingFileHandler(log_file, maxBytes=10 * 1024 * 1024, backupCount=5)
file_handler.setFormatter(log_formatter)
file_handler.setLevel(logging.INFO)

console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)
console_handler.setLevel(logging.DEBUG)

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
logger.addHandler(file_handler)
logger.addHandler(console_handler)


# Maintenance mode authentication
AUTH_COOKIE_NAME = 'auth_token'
VALID_AUTH_TOKEN = '49c380da1a66e2843d383508ae6685e36254908be770c65edb63980166118420'
enable_maintenance_mode = False
enable_maintenance_mode_recon = True

# Flask - CORS Prerequisites
app = Flask(__name__)
CORS(app, resources={
    r"/*": {
        "origins": re.compile(r"chrome-extension://.+")
    }
})


# Store the received cookies and associated UUIDs and URLs
cookie_store = {}


# -----------------------------------------------
# Function to prevent session expiration 
# leading to KeyError
# -----------------------------------------------

def validate_uuid(f):
    @wraps(f)
    def decorated_function(uuid, *args, **kwargs):
        try:
            if uuid not in cookie_store:
                return jsonify({
                    'status': 'error',
                    'message': 'Session expired or invalid. Please start a new download.'
                }), 400
            return f(uuid, *args, **kwargs)
        except KeyError:
            logger.warning(f"KeyError accessing uuid {uuid} - session likely expired")
            return jsonify({
                'status': 'error',
                'message': 'Session expired or invalid. Please start a new download.'
            }), 400
    return decorated_function





# -----------------------------------------------------------------------------------------------------------------------------
#
# Flask App routes
# Index:
#   / : Displays home page
#   /store-auth : Saves data sent by extension under <uuid>
#   /start-capture/<uuid> : Starting point from extension, performs adblock check
#   /choose/<uuid> : Shows a choice screen to select capturing method
#   /proceed_with_interception/<uuid> : Runs interception for document
#   /proceed_with_reconstruction/<uuid> : Runs reconstruction for document
#   /check-status/<uuid> : Check whether capture is finished or not
#   /retrieve/<uuid> : Accesses the captured file for download
#
# -----------------------------------------------------------------------------------------------------------------------------


# Home page route

@app.route('/')
def home():
    return render_template('home.html')


# Route to receive cookies and URL from the Chrome extension

@app.route('/store-auth', methods=['POST'])
def store_auth():
    try:
        # Generate a unique UUID
        session_id = str(uuid.uuid4())

        # Extract cookies and URL from the request
        data = request.json
        cookies = data.get('cookies', [])
        url = data.get('url', '')

        # Store the cookies, URL, and timestamp with the associated UUID
        cookie_store[session_id] = {
            'cookies': cookies,
            'url': url,
            'start_timestamp': datetime.now(),
            'method': "declare",
            'ocr': False,
            'page_count': 0,
            'process_start_timestamp': None,
            'finish_timestamp': None,
            'status': "Please wait while the file is being processed. Page is being loaded.",
            'keep_alive': datetime.now()
        }
        logger.info("Received cookies and URL from extension for session: %s", session_id)

        with open(f'{BASE_PATH}logs/inits.csv', mode='a', newline='', encoding='utf-8') as file:
            writer = csv.writer(file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            writer.writerow([session_id, datetime.now(), request.cookies.get('client_ip', 'IP not found'), request.headers.get('User-Agent'), cookie_store[session_id]['url'], False])



        # Respond with the UUID
        return jsonify({'status': 'success', 'uuid': session_id}), 200
    except Exception as e:
        exc_json = jsonify({'status': 'error', 'message': str(e)})
        logger.exception("Exception during storing data: %s", exc_json)
        return exc_json, 400


# Route to start interception capture - start with adblock check

@app.route('/start-capture/<uuid>', methods=['GET'])
@validate_uuid
def start_capture(uuid):
    auth_token = request.cookies.get(AUTH_COOKIE_NAME)
    if enable_maintenance_mode and auth_token != VALID_AUTH_TOKEN:
        # If maintenance mode is enabled and the auth token is invalid, show the maintenance page
        logger.debug("User not authenticated, showing maintenance page, token:  %s", auth_token)
        return render_template('maintenance.html', uuid=uuid)
    else:
        return redirect(url_for('choose', uuid=uuid))

    # Adblock Check temporarily disabled
    # return render_template('adblock-check.html', uuid=uuid)


# Choose the capturing method screen

@app.route('/choose/<uuid>', methods=['GET'])
@validate_uuid
def choose(uuid):
    if uuid not in cookie_store:
        return jsonify({'status': 'error', 'message': 'Invalid UUID'}), 400

    url = cookie_store[uuid]['url']
    page_count = asyncio.run(get_pages(url))  # <== wrap your async call
    cookie_store[uuid]['page_count'] = page_count
    time_complexity = format_seconds(10 + (page_count * 3.7))

    auth_token = request.cookies.get(AUTH_COOKIE_NAME)
    if enable_maintenance_mode_recon and auth_token != VALID_AUTH_TOKEN:
        logger.debug("User not authenticated, showing maintenance page, token:  %s", auth_token)
        return render_template('choose_maintenance.html', time_complexity=time_complexity, uuid=uuid)
    else:
        return render_template('choose.html', time_complexity=time_complexity, uuid=uuid)
    

# Choose whether you want OCR screen

@app.route('/choose-ocr/<uuid>', methods=['GET'])
@validate_uuid
def choose_ocr(uuid):
    time_complexity_yes = format_seconds(10 + (cookie_store[uuid]['page_count'] * 11.4))
    time_complexity_no = format_seconds(10 + (cookie_store[uuid]['page_count'] * 3.7))
    return render_template('ocr.html', time_complexity_yes=time_complexity_yes, time_complexity_no=time_complexity_no, uuid=uuid)


# Proceed with interception

@app.route('/proceed_with_interception/<uuid>', methods=['GET'])
@validate_uuid
def proceed_with_interception(uuid):
    cookie_store[uuid]['method'] = "intercept"
    cookie_store[uuid]['start_timestamp'] = datetime.now()

    update_log_for_pass(uuid)

    # Start HAR capture in a separate thread to avoid blocking the request
    threading.Thread(target=run_har_capture, args=(uuid,)).start()

    # Redirect to the loading page after initiating the capture
    return render_template('loading_intercept.html', uuid=uuid)


# Proceed with reconstruction

@app.route('/proceed_with_reconstruction/<uuid>', methods=['GET'])
@validate_uuid
def proceed_with_reconstruction(uuid):
    cookie_store[uuid]['method'] = "reconstruct"
    cookie_store[uuid]['start_timestamp'] = datetime.now()

    update_log_for_pass(uuid)

    if request.args.get('ocr') == 'yes':
        cookie_store[uuid]['ocr'] = True
    elif request.args.get('ocr') == 'no':
        cookie_store[uuid]['ocr'] = False


     # Create a wrapper function that runs the async function in an event loop
    def run_async_reconstruction(uuid):
        asyncio.run(run_reconstruction(uuid))

    # Start the wrapper function in a thread
    threading.Thread(target=run_async_reconstruction, args=(uuid,)).start()

    # Redirect to the loading page after initiating the capture
    return render_template('loading_reconstruct.html', uuid=uuid, PAGE_LIMIT=RECONSTRUCTION_PAGE_LIMIT)


# Route to check HAR capture status

@app.route('/check-status/<uuid>', methods=['GET'])
@validate_uuid
def check_status(uuid):
    cookie_store[uuid]['keep_alive'] = datetime.now()
    if cookie_store[uuid]['method'] == "intercept":
        har_path = f"{BASE_PATH}cache/network_trace_{uuid}.har"
        if os.path.exists(har_path):
            return jsonify({'status': 'complete', 'message': f'HAR file {har_path} captured.'}), 200
        else:
            return jsonify({'status': 'processing', 'message': 'HAR capture is still in progress.'}), 202
    elif cookie_store[uuid]['method'] == "reconstruct":
        if cookie_store[uuid]['ocr']:
            pdf_ocr_path = f"{BASE_PATH}cache/recon_final_{uuid}.pdf"
            if os.path.exists(pdf_ocr_path):
                return jsonify({'status': 'complete', 'message': f'PDF file {pdf_ocr_path} reconstructed.'}), 200
            else:
                return jsonify({'status': 'processing', 'message': cookie_store[uuid]['status']}), 202
        else:
            pdf_no_ocr_path = f"{BASE_PATH}cache/recon_{uuid}.pdf"
            if os.path.exists(pdf_no_ocr_path):
                return jsonify({'status': 'complete', 'message': f'PDF file {pdf_no_ocr_path} reconstructed.'}), 200
            else:
                return jsonify({'status': 'processing', 'message': cookie_store[uuid]['status']}), 202
    else:
        return jsonify({'status': 'error', 'message': 'Invalid uuid'}), 400



# Route to retrieve captured file

@app.route('/retrieve/<uuid>', methods=['GET'])
@validate_uuid
def retrieve_pdf(uuid):
    # Statistical/technical data collection
    retrieval_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ip_address = request.cookies.get('client_ip', 'IP not found')
    user_agent = request.headers.get('User-Agent')
    requested_url = cookie_store[uuid]['url']
        

    # In case of interception
    if cookie_store[uuid]['method'] == "intercept":
        har_path = f"{BASE_PATH}cache/network_trace_{uuid}.har"

        load_time = cookie_store[uuid]['finish_timestamp'] - cookie_store[uuid]['start_timestamp']
        process_time = load_time

        if not os.path.exists(har_path):
            return jsonify({'status': 'error', 'message': 'HAR file not found'}), 404

        try:
            # Open the HAR file as a zip archive
            with zipfile.ZipFile(har_path, 'r') as har_archive:
                pdf_filename = None

                # Iterate over files to find the PDF
                for file_info in har_archive.infolist():
                    if file_info.filename.startswith('resources/') and file_info.filename.endswith('.pdf'):
                        pdf_filename = file_info.filename
                        logger.info("PDF File found in HAR")
                        break

                if not pdf_filename:
                    logger.warning("Could not find PDF file in HAR")
                    # Write data to CSV
                    with open(f'{BASE_PATH}logs/log.csv', mode='a', newline='', encoding='utf-8') as file:
                        writer = csv.writer(file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                        writer.writerow([retrieval_timestamp, ip_address, user_agent, requested_url, "failed", "intercept", "False", load_time, process_time, cookie_store[uuid]['page_count']])
                    with Controller.from_port(port=9051) as controller:
                        controller.authenticate()  # Optional: Authenticate if needed
                        controller.signal(Signal.NEWNYM)  # Request a new circuit
                        logger.info("New Tor circuit created.")
                    return jsonify({'status': 'error', 'message': 'PDF missing. Try the download again or switch to reconstruction mode'}), 404

                # Read the PDF file from the HAR archive
                with har_archive.open(pdf_filename) as pdf_file:
                    pdf_bytes = pdf_file.read()
                    # Create a BytesIO object to serve the PDF file
                    pdf_io = io.BytesIO(pdf_bytes)
                    pdf_io.seek(0)  # Seek to the start of the file

            # Write data to CSV
                    with open(f'{BASE_PATH}logs/log.csv', mode='a', newline='', encoding='utf-8') as file:
                        writer = csv.writer(file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                        writer.writerow([retrieval_timestamp, ip_address, user_agent, requested_url, "success", "intercept", "False", load_time, process_time, cookie_store[uuid]['page_count']])


                    # Send the PDF file to the client
                    return send_file(pdf_io, as_attachment=True, download_name=uuid+'.pdf', mimetype='application/pdf')
                
        except Exception as e:
            exc_json = jsonify({'status': 'error', 'message': str(e)})
            logger.exception("Exception during PDF retrieval: %s", exc_json)
            return exc_json, 500
        

    elif (cookie_store[uuid]['method'] == "reconstruct"):
        
        load_time = cookie_store[uuid]['process_start_timestamp'] - cookie_store[uuid]['start_timestamp']
        process_time = cookie_store[uuid]['finish_timestamp'] - cookie_store[uuid]['process_start_timestamp']

        if cookie_store[uuid]['ocr']:
            pdf_path = f"{BASE_PATH}cache/recon_final_{uuid}.pdf"
        else:
            pdf_path = f"{BASE_PATH}cache/recon_{uuid}.pdf"
        
        if not os.path.exists(pdf_path):
            exc_json = jsonify({'status': 'error', 'message': 'PDF file not found'}), 404
            logger.exception("Exception during PDF retrieval: %s", exc_json)

            with open(f'{BASE_PATH}logs/log.csv', mode='a', newline='', encoding='utf-8') as file:
                        writer = csv.writer(file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                        writer.writerow([retrieval_timestamp, ip_address, user_agent, requested_url, "failed", "reconstruct", cookie_store[uuid]['ocr'], load_time, process_time, cookie_store[uuid]['page_count']])

            return exc_json, 500


        with open(f'{BASE_PATH}logs/log.csv', mode='a', newline='', encoding='utf-8') as file:
            writer = csv.writer(file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            writer.writerow([retrieval_timestamp, ip_address, user_agent, requested_url, "success", "reconstruct", cookie_store[uuid]['ocr'], load_time, process_time, cookie_store[uuid]['page_count']])


        try:
            # Send the PDF file to the client
            return send_file(pdf_path, as_attachment=True, download_name=uuid+'.pdf', mimetype='application/pdf')
        except Exception as e:
            exc_json = jsonify({'status': 'error', 'message': str(e)})
            logger.exception("Exception during PDF retrieval: %s", exc_json)
            return exc_json, 500

    del cookie_store[uuid]




# -----------------------------------------------------------------------------------------------------------------------------
#
# Assisting functions
# contains capture mechanisms, and utility functions
#
# -----------------------------------------------------------------------------------------------------------------------------



# ----------------------------------------------------
# Function which gathers the page amount of the 
# required document
# ----------------------------------------------------
#
# Unit test required!
#
# -----------------------------------------------------

async def get_pages(url):
    async with async_playwright() as p:
        # Launch the browser
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()

        # Go to the target website
        await page.goto(url, wait_until="networkidle")  # Replace with your desired URL

        # Get all elements with the class "ml-1"
        elements = await page.query_selector_all('.ml-1')

        if elements:
            # Iterate through the elements
            for idx, element in enumerate(elements, 1):
                text_content = await element.text_content()
                return int(text_content)
        else:
            logger.warning("No elements with the class 'ml-1' were found.")
            return 20

        # Close the browser
        await browser.close()


# ----------------------------------------------------
# Separate function to run Playwright and capture
# the HAR file in the background (Interception)
# ----------------------------------------------------

def run_har_capture(uuid):
    cookies = cookie_store[uuid]['cookies']
    url = cookie_store[uuid]['url']

    # ----------------------------------------------------------
    # Case 1: Small document, use TOR and 30 seconds as timeout
    # ----------------------------------------------------------

    def run_quick(playwright):
        # Launch the browser and create a new context
        browser = playwright.chromium.launch()
        context = browser.new_context(proxy={
            'server': 'socks5://127.0.0.1:9050'  # Using Tor's default SOCKS5 proxy
        })

        ip_check = context.new_page()
        ip_check.goto('https://api.ipify.org?format=json')
        ip_info = ip_check.locator('body').inner_text()
        logger.info("IP / Tor Node: %s", ip_info)


        # Insert cookies into the context before navigating to the site
        for cookie in cookies:
            cookie_data = {
                'name': cookie['name'],
                'value': cookie['value'],
                'domain': cookie['domain'],
                'path': cookie['path'] if cookie.get('path') else '/',
                'secure': cookie.get('secure', False),
                'httpOnly': cookie.get('httpOnly', False),
                'sameSite': cookie.get('sameSite', 'None')
            }
            if cookie_data['sameSite'] not in ['Strict', 'Lax', 'None']:
                cookie_data['sameSite'] = 'None'
            if 'expirationDate' in cookie:
                cookie_data['expires'] = cookie['expirationDate']
            context.add_cookies([cookie_data])

        # Start recording the network activity to a HAR file
        context.tracing.start(screenshots=True, snapshots=True)

        # Open a new page
        page = context.new_page()

        # Navigate to the webpage that was saved with the UUID
        page.goto(url)

        # Wait for the page to fully load (adjust the timeout as necessary)
        page.wait_for_timeout(30000)  # Wait for 30 seconds

        # Stop recording the network activity and save the HAR file
        har_path = f"{BASE_PATH}cache/network_trace_{uuid}.har"
        context.tracing.stop(path=har_path)

        # Close the browser
        browser.close()

        cookie_store[uuid]['finish_timestamp'] = datetime.now()
        logger.info("Capture completed in %s", cookie_store[uuid]['finish_timestamp'] - cookie_store[uuid]['start_timestamp'])


    # ----------------------------------------------------------
    # Case 2: Larger document, no TOR and 2 minutes as timeout
    # ----------------------------------------------------------

    def run_long(playwright):
        # Launch the browser and create a new context
        browser = playwright.chromium.launch()
        context = browser.new_context()

        ip_check = context.new_page()
        ip_check.goto('https://api.ipify.org?format=json')
        ip_info = ip_check.locator('body').inner_text()
        logger.info("IP / Tor Node: %s", ip_info)


        # Insert cookies into the context before navigating to the site
        for cookie in cookies:
            cookie_data = {
                'name': cookie['name'],
                'value': cookie['value'],
                'domain': cookie['domain'],
                'path': cookie['path'] if cookie.get('path') else '/',
                'secure': cookie.get('secure', False),
                'httpOnly': cookie.get('httpOnly', False),
                'sameSite': cookie.get('sameSite', 'None')
            }
            if cookie_data['sameSite'] not in ['Strict', 'Lax', 'None']:
                cookie_data['sameSite'] = 'None'
            if 'expirationDate' in cookie:
                cookie_data['expires'] = cookie['expirationDate']
            context.add_cookies([cookie_data])

        # Function to scroll the page down periodically
        def scroll_down(page, scroll_interval=1000, total_duration=100000):  # Scroll for 2 minutes (120000 ms)
            end_time = time.time() + total_duration / 1000  # Convert total duration to seconds

            while time.time() < end_time:
                # Scroll down by the height of the page
                page.evaluate("window.scrollBy(0, document.body.scrollHeight)")

                # Wait for a short interval before scrolling again
                page.wait_for_timeout(scroll_interval)  # Wait for the specified scroll interval

        # Start recording the network activity to a HAR file
        context.tracing.start(screenshots=True, snapshots=True)

        # Open a new page
        page = context.new_page()

        # Navigate to the webpage that was saved with the UUID
        page.goto(url)

        button_selector = '.sc-dcJsrY.eLpiYF'  # Use a single class selector
        page.wait_for_selector(button_selector, timeout=20000)  # Adjust timeout as necessary

        # Click the button once it appears
        page.click(button_selector)


        # Scroll down while waiting for the page to fully load (scroll for 2 minutes)
        scroll_down(page, scroll_interval=1000, total_duration=100000)  # Scroll every 1 second for 2 minutes

        # Stop recording the network activity and save the HAR file
        har_path = f"{BASE_PATH}cache/network_trace_{uuid}.har"
        context.tracing.stop(path=har_path)


        # Close the browser
        browser.close()
        cookie_store[uuid]['finish_timestamp'] = datetime.now()
        logger.info("Capture completed in %s", cookie_store[uuid]['finish_timestamp'] - cookie_store[uuid]['start_timestamp'])


    # ----------------------------------------------------------
    # Determine page size, decide, and run
    # ----------------------------------------------------------

    if (cookie_store[uuid]['page_count'] <= 35):
        logger.info("Using TOR and short timeout")
        # Run Playwright and capture the HAR file
        with sync_playwright() as playwright:
            run_quick(playwright)
    else:
        logger.info("Using no IP mask, long timeout")
        with sync_playwright() as playwright:
            run_long(playwright)


# ----------------------------------------------------
# Seperate function to reconstruct PDF file
# (Reconstruction)
# ----------------------------------------------------

async def run_reconstruction(uuid):
    cookies = cookie_store[uuid]['cookies']
    url = cookie_store[uuid]['url']
    pdf_buffers = []

    async def run(playwright, num_pages):
        # Launch the browser and create a new context
        browser = await playwright.chromium.launch()

        # Disabled
#        context = await browser.new_context(proxy={
#            'server': 'socks5://127.0.0.1:9050'  # Using Tor's default SOCKS5 proxy
#        }, device_scale_factor=3)

        context = await browser.new_context(device_scale_factor=3)

        # Perform the IP check (optional)
        ip_check = await context.new_page()
        await ip_check.goto('https://api.ipify.org?format=json')
        ip_info = await ip_check.locator('body').inner_text()
        logger.info("IP / Tor Node: %s", ip_info)

        # Insert cookies into the context
        for cookie in cookies:
            cookie_data = {
                'name': cookie['name'],
                'value': cookie['value'],
                'domain': cookie['domain'],
                'path': cookie.get('path', '/'),
                'secure': cookie.get('secure', False),
                'httpOnly': cookie.get('httpOnly', False),
                'sameSite': cookie.get('sameSite', 'None')
            }
            if cookie_data['sameSite'] not in ['Strict', 'Lax', 'None']:
                cookie_data['sameSite'] = 'None'
            if 'expirationDate' in cookie:
                cookie_data['expires'] = cookie['expirationDate']
            await context.add_cookies([cookie_data])

        # Open the main page and navigate to the target URL
        page = await context.new_page()
        await page.goto(url)
        await page.wait_for_load_state("networkidle")

        cookie_store[uuid]['process_start_timestamp'] = datetime.now()
        logger.info("Load finished, Reconstruction started at %s", cookie_store[uuid]['process_start_timestamp'])

        max_pages = min(num_pages, RECONSTRUCTION_PAGE_LIMIT)

        # For each page container, capture the canvas as a PDF page
        for i in range(1, max_pages + 1):
            logger.info(f"Processing page container {i}")
            pdf_fragment = await capture_canvas_as_pdf(page, i)
            pdf_buffers.append(pdf_fragment)

            # Inform the user
            cookie_store[uuid]['status'] = f"Processing page {i} of {num_pages}."



        # Close the browser
        await browser.close()
        

    # Run Playwright with the number of pages determined asynchronously
    async with async_playwright() as playwright:
        num_pages = cookie_store[uuid]['page_count']
        await run(playwright, num_pages)
    
    # Merge all PDF pages into one document
    merger = PdfMerger()
    for pdf in pdf_buffers:
        merger.append(io.BytesIO(pdf))
    output = io.BytesIO()

    merger.write(output)
    merger.close()
    with open(f"{BASE_PATH}cache/recon_{uuid}.pdf", "wb") as f:
        f.write(output.getvalue())
    logger.info("PDF saved as %s.pdf", uuid)

    # Perform OCR if requested
    if cookie_store[uuid]['ocr']:
        cookie_store[uuid]['status'] = "Performing text optimization. This can take a while."
        input_pdf = f"{BASE_PATH}cache/recon_{uuid}.pdf"
        output_pdf = f"{BASE_PATH}cache/recon_final_{uuid}.pdf"
        ocrmypdf.ocr(input_pdf, output_pdf, deskew=True)
        logger.info("OCR complete. Searchable PDF saved as %s", output_pdf)
    
    cookie_store[uuid]['finish_timestamp'] = datetime.now()
    logger.info("Reconstruction completed in %s", cookie_store[uuid]['finish_timestamp'] - cookie_store[uuid]['start_timestamp'])


# ----------------------------------------------------
# Function to translate html canvas elements to PDF
# ----------------------------------------------------

async def capture_canvas_as_pdf(page, page_index):
    # Construct the selector for the page container
    container_selector = f"#viewer > #pageContainer{page_index}"
    container = page.locator(container_selector)
    await container.wait_for(state="visible", timeout=10000)  # Wait until the container is visible

    # Locate the canvas element within the container and wait for it to be visible
    canvas_locator = container.locator("canvas")
    await canvas_locator.wait_for(state="visible", timeout=10000)
    
    # Scroll the container into view if necessary
    await container.scroll_into_view_if_needed()

    # Use JavaScript to convert the canvas to a data URL (base64 encoded PNG)
    canvas_data_url = await canvas_locator.evaluate("canvas => canvas.toDataURL('image/png')")
    header, base64_data = canvas_data_url.split(',', 1)
    image_bytes = base64.b64decode(base64_data)
    
    # Open the image with Pillow
    image = Image.open(io.BytesIO(image_bytes))

    # Define A4 dimensions at 300 DPI
    dpi = 300
    a4_size = (int(8.27 * dpi), int(11.69 * dpi))  # roughly (2481, 3508)

    # If the image is smaller than the A4 size, upscale it to fill as much as possible
    # Calculate the new size preserving the aspect ratio
    img_ratio = image.width / image.height
    a4_ratio = a4_size[0] / a4_size[1]
    
    if img_ratio > a4_ratio:
        # Image is wider relative to A4: width is the limiting factor
        new_width = a4_size[0]
        new_height = int(new_width / img_ratio)
    else:
        # Image is taller: height is the limiting factor
        new_height = a4_size[1]
        new_width = int(new_height * img_ratio)
    
    # Resize the image with high-quality resampling
    image_resized = image.resize((new_width, new_height), Image.LANCZOS)
    
    # Create a blank white A4 page (high resolution)
    a4_page = Image.new("RGB", a4_size, "white")
    
    # Center the resized image on the A4 page
    offset = ((a4_size[0] - new_width) // 2, (a4_size[1] - new_height) // 2)
    a4_page.paste(image_resized, offset)
    
    # Save the A4 page as a PDF in memory with high DPI
    pdf_bytes_io = io.BytesIO()
    a4_page.save(pdf_bytes_io, "PDF", resolution=dpi)
    return pdf_bytes_io.getvalue()


# ----------------------------------------------------
# Function that destroys user auth cookies
# ----------------------------------------------------

def clean_expired_cookies():
    # Get current time
    now = datetime.now()

    # Calculate the expiration time (5 minutes)
    expiration_time = timedelta(minutes=5)

    # Create a list of keys to delete
    keys_to_delete = [key for key, value in cookie_store.items()
                      if (now - value['start_timestamp'] > expiration_time) and (now - value['keep_alive'] > timedelta(minutes=2))]

    # Remove expired entries
    for key in keys_to_delete:
        del cookie_store[key]

    logger.info("Cleaned expired cookies: %s", keys_to_delete)


# ----------------------------------------------------
# Function rewriting seconds to readable text
# ----------------------------------------------------

def format_seconds(total_seconds):
    minutes = int(total_seconds // 60)
    seconds = int(total_seconds % 60)

    # Handle plural/singular formatting
    min_label = "min"
    sec_label = "s"

    return f"{minutes} {min_label}, {seconds} {sec_label}"


# ----------------------------------------------------
# Scheduler that repeats the coookie removal functions
# ----------------------------------------------------

def start_scheduler():
    scheduler = BackgroundScheduler()
    # Run the cleanup function every 1 minute
    scheduler.add_job(func=clean_expired_cookies, trigger="interval", minutes=1)
    scheduler.start()


# ----------------------------------------------------
# Function to log the passing of the choice screen
# ----------------------------------------------------

def update_log_for_pass(uuid):
    updated_rows = []

    with open(f'{BASE_PATH}logs/inits.csv', mode='r', newline='') as infile:
        reader = csv.DictReader(infile)
        fieldnames = reader.fieldnames
        for row in reader:
            if row[fieldnames[0]] == uuid:  # Check first column for the UUID
                row[fieldnames[5]] = "True"
            updated_rows.append(row)

    # Step 2: Write the updated data back to the CSV
    with open(f'{BASE_PATH}logs/inits.csv', mode='w', newline='') as outfile:
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(updated_rows)


# -----------------------------------------------------------------------------------------------------------------------------


# Start the scheduler immediately when the app is created
start_scheduler()

# Start the app
if __name__ == '__main__':
    app.run(debug=True)