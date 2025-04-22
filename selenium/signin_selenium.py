from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time
import unittest

class TestSignup(unittest.TestCase):
    def setUp(self):
        print("\n=== Setting up test environment ===")
        options = webdriver.ChromeOptions()
        options.add_argument('--ignore-certificate-errors')
        options.add_argument('--ignore-ssl-errors')
        self.driver = webdriver.Chrome(options=options)
        self.driver.get("http://127.0.0.1:8000/signup/")
        self.driver.maximize_window()
        print("Browser launched and navigated to signup page")

    def test_valid_signup(self):
        print("\nExecuting Valid Signup Test Case")
        # Generate unique email using timestamp
        unique_email = f"validuser_{int(time.time())}@example.com"
        
        self.fill_form({
            "name": "Valid User",
            "email": unique_email,
            "password": "ValidPassword123!",
            "confirm_password": "ValidPassword123!",
            "phone": "1234567890",
            "address": "123 Valid Street, City"
        })
        
        # Submit the form
        submit_button = self.driver.find_element(By.XPATH, "//input[@type='submit']")
        submit_button.click()
        
        try:
            # Wait for either success alert or redirect
            WebDriverWait(self.driver, 10).until(
                lambda driver: driver.current_url != "http://127.0.0.1:8000/signup/" or
                EC.presence_of_element_located((By.CLASS_NAME, "swal2-success"))
            )
            
            # Check if we're still on the signup page (might have success alert)
            if "signup" in self.driver.current_url.lower():
                # Handle success alert
                sweet_alert = self.driver.find_element(By.CLASS_NAME, "swal2-popup")
                success_title = sweet_alert.find_element(By.CLASS_NAME, "swal2-title").text
                self.assertIn("Success", success_title)
                
                # Click confirm button
                confirm_button = sweet_alert.find_element(By.CLASS_NAME, "swal2-confirm")
                confirm_button.click()
                
                # Verify final redirect
                WebDriverWait(self.driver, 5).until(
                    lambda driver: "login" in driver.current_url.lower()
                )
            
            print("Signup successful and redirected properly")
            
        except Exception as e:
            print(f"Error during signup: {str(e)}")
            print("Current page source:")
            print(self.driver.page_source[:500])
            self.fail("Valid signup test failed")

    def fill_form(self, data):
        """Helper method to fill the signup form"""
        self.driver.find_element(By.ID, "name").send_keys(data["name"])
        self.driver.find_element(By.ID, "email").send_keys(data["email"])
        self.driver.find_element(By.ID, "password").send_keys(data["password"])
        self.driver.find_element(By.ID, "confirmPassword").send_keys(data["confirm_password"])
        self.driver.find_element(By.ID, "phone").send_keys(data["phone"])
        self.driver.find_element(By.ID, "address").send_keys(data["address"])

    def tearDown(self):
        print("\nCleaning up: Closing browser")
        self.driver.quit()

if __name__ == "__main__":
    unittest.main()
