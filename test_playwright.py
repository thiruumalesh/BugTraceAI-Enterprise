from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch(headless=False)
    page = browser.new_page()

    page.goto("http://127.0.0.1:3000")

    print(page.title())

    page.wait_for_timeout(5000)

    browser.close()
