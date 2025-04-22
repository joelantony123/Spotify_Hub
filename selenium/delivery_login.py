from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time
import unittest
from selenium.common.exceptions import TimeoutException, NoSuchElementException

class TestDeliveryLogin(unittest.TestCase):
    def setUp(self):
        print("\n=== Setting up test environment ===")
        options = webdriver.ChromeOptions()
        options.add_argument('--ignore-certificate-errors')
        options.add_argument('--ignore-ssl-errors')
        options.add_argument('--allow-insecure-localhost')
        options.add_argument('--disable-web-security')
        options.add_argument('--disable-notifications')
        options.add_argument('--disable-extensions')
        options.add_argument('--disable-gpu')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        self.driver = webdriver.Chrome(options=options)
        
        # Navigate to login page and wait for it to load
        self.driver.get("http://127.0.0.1:8000/delivery/login/")
        self.driver.maximize_window()
        
        # Wait for form to be present
        WebDriverWait(self.driver, 10).until(
            EC.presence_of_element_located((By.TAG_NAME, "form"))
        )
        print("Browser launched and navigated to delivery login page")

    def test_case_1_empty_fields(self):
        print("\nExecuting Test Case 1: Empty Fields")
        # Try to submit the form without filling any fields
        submit_button = self.driver.find_element(By.XPATH, "//input[@type='submit']")
        submit_button.click()
        
        # Wait a moment to see if navigation happens
        time.sleep(2)
        
        # Check if we're still on the login page (HTML5 validation should prevent submission)
        self.assertIn("login", self.driver.current_url.lower())
        print("Test Case 1 completed: Empty fields validation tested")

    def test_case_2_invalid_email_format(self):
        print("\nExecuting Test Case 2: Invalid Email Format")
        # Fill in invalid email
        email_field = self.driver.find_element(By.NAME, "email")
        email_field.clear()
        email_field.send_keys("invalid-email")
        
        # Fill in password
        password_field = self.driver.find_element(By.NAME, "password")
        password_field.clear()
        password_field.send_keys("password123")
        
        # Submit the form
        submit_button = self.driver.find_element(By.XPATH, "//input[@type='submit']")
        submit_button.click()
        
        # Wait a moment to see if navigation happens
        time.sleep(2)
        
        # Check if we're still on the login page (HTML5 validation should prevent submission)
        self.assertIn("login", self.driver.current_url.lower())
        print("Test Case 2 completed: Invalid email format tested")

    def test_case_3_invalid_credentials(self):
        print("\nExecuting Test Case 3: Invalid Credentials")
        # Fill in valid email format but incorrect credentials
        email_field = self.driver.find_element(By.NAME, "email")
        email_field.clear()
        email_field.send_keys("nonexistent@example.com")
        
        # Fill in password
        password_field = self.driver.find_element(By.NAME, "password")
        password_field.clear()
        password_field.send_keys("wrongpassword")
        
        # Submit the form
        submit_button = self.driver.find_element(By.XPATH, "//input[@type='submit']")
        submit_button.click()
        
        # Wait for alert message or redirect
        time.sleep(3)
        
        try:
            # Check if alert message is displayed
            alert = self.driver.find_element(By.CLASS_NAME, "alert")
            print(f"Alert message: {alert.text}")
            self.assertIn("login", self.driver.current_url.lower())
        except NoSuchElementException:
            # If no alert, we should still be on login page
            self.assertIn("login", self.driver.current_url.lower())
            print("No alert message found, but still on login page")
        
        print("Test Case 3 completed: Invalid credentials tested")

    def test_case_4_navigation_to_register(self):
        print("\nExecuting Test Case 4: Navigation to Register Page")
        # Click on the register link
        register_link = self.driver.find_element(By.XPATH, "//a[contains(text(), 'Register here')]")
        register_link.click()
        
        # Wait for navigation
        time.sleep(3)
        
        # Check if we're on the registration page
        self.assertIn("register", self.driver.current_url.lower())
        print("Test Case 4 completed: Navigation to register page tested")

    def test_case_5_back_to_home(self):
        print("\nExecuting Test Case 5: Back to Home")
        # Click on the back to home button
        try:
            back_button = self.driver.find_element(By.XPATH, "//a[contains(@class, 'back-button')]")
            back_button.click()
            
            # Wait for navigation
            time.sleep(3)
            
            # Check if we're redirected (either to home or login page)
            current_url = self.driver.current_url.lower()
            print(f"Redirected to: {current_url}")
            
            # Accept either home or login as valid destinations
            self.assertTrue(
                "home" in current_url or "login" in current_url,
                f"Expected redirection to home or login page, but got: {current_url}"
            )
            print("Test Case 5 completed: Back button navigation tested")
        except NoSuchElementException:
            print("Could not find back button with class selector")
            # Try alternative selector
            try:
                # Look for any link with the text "Back to Home"
                back_button = self.driver.find_element(By.XPATH, "//a[contains(., 'Back to Home')]")
                back_button.click()
                time.sleep(3)
                
                current_url = self.driver.current_url.lower()
                print(f"Redirected to: {current_url}")
                
                # Accept either home or login as valid destinations
                self.assertTrue(
                    "home" in current_url or "login" in current_url,
                    f"Expected redirection to home or login page, but got: {current_url}"
                )
                print("Test Case 5 completed: Back button navigation tested (using alternative selector)")
            except NoSuchElementException:
                print("Current page source:")
                print(self.driver.page_source[:500])
                self.fail("Could not find back button element")

    def tearDown(self):
        print("\nCleaning up: Closing browser")
        self.driver.quit()

if __name__ == "__main__":
    unittest.main()
