import json
import os
import time

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from webdriver_manager.chrome import ChromeDriverManager

from questions import BASE_URL, question_generator


class GenerateQuestions:
    def __init__(self, teardown=False):

        s = Service(ChromeDriverManager().install())
        self.options = webdriver.ChromeOptions()

        # --- Add these two lines here ---
        self.options.add_argument("--headless")
        self.options.add_argument("--window-size=1920,1080")
        # ---------------------------------

        # removed headless so the browser window is visible
        # ensure window is visible and starts maximized
        self.options.add_argument('--start-maximized')
        self.teardown = teardown
        # keep chrome open after chromedriver exits
        self.options.add_experimental_option("detach", True)
        self.options.add_experimental_option(
            "excludeSwitches",
            ['enable-logging'])
        self.driver = webdriver.Chrome(
            options=self.options,
            service=s)
        self.driver.implicitly_wait(50)
        self.collections_url = []
        super(GenerateQuestions, self).__init__()

    def __enter__(self):
        self.driver.get(BASE_URL)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.teardown:
            self.driver.quit()

    def toggle_deep_research(self):
        wait = WebDriverWait(self.driver, 20)

        xpath = '//button[.//span[normalize-space(text())="Fast"]]'
        btn = wait.until(EC.element_to_be_clickable((By.XPATH, xpath)))
        btn.click()

        xpath_primary = "//div[@role='menuitem' and .//span[normalize-space(text())='Deep Research']]"
        menu_item = wait.until(EC.element_to_be_clickable((By.XPATH, xpath_primary)))
        menu_item.click()

    def ask_question(self, question_gotten):
        wait = WebDriverWait(self.driver, 1200)

        try:
            self.driver.get(BASE_URL)

            # # wait for the form containing the textarea
            form = wait.until(
                EC.presence_of_element_located((By.CSS_SELECTOR, 'form'))
            )

            # find the textarea inside the form
            textarea = form.find_element(By.CSS_SELECTOR, 'textarea')
            self.toggle_deep_research()

            # type the question
            textarea.click()
            textarea.clear()
            formatted_question = question_generator(question_gotten)

            # Use JavaScript to set the textarea value directly. It's more reliable for large text.
            self.driver.execute_script("arguments[0].value = arguments[1];", textarea, formatted_question)
            # Dispatch an 'input' event to make sure the web application detects the change.
            self.driver.execute_script("arguments[0].dispatchEvent(new Event('input', { bubbles: true }));",
                                       textarea)
            textarea.send_keys(".. ")

            textarea.send_keys(Keys.ENTER)

            time.sleep(10)
            current_url = self.driver.current_url

            # add the current url to collections
            self.save_to_questions(question_gotten, current_url)
        except Exception as a:
            print(f"There was an error in index : {a}")

            # In your Deepwiki class where you save to collections.json

    def save_to_questions(self, question_gotten, url):
        """Save question and URL to collections.json"""
        collections_file = "questions.json"

        # Load existing data or start fresh
        try:
            if os.path.exists(collections_file):
                with open(collections_file, "r") as f:
                    content = f.read().strip()
                    data = json.loads(content) if content else []
            else:
                data = []
        except json.JSONDecodeError:
            print("Invalid collections.json, creating new file")
            data = []

        # Add new entry
        data.append({
            "question": question_gotten,
            "url": url,
        })

        # Save with proper formatting
        try:
            with open(collections_file, "w") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Error saving to collections: {e}")
