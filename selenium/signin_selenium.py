from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time
import unittest

class TestSignup(unittest.TestCase):
    def setUp(self):
        print("\n=== Setting up test environment ===")
        self.driver = webdriver.Chrome()
        self.driver.get("http://127.0.0.1:8000/signup/")
        self.driver.maximize_window()
        print("Browser launched and navigated to signup page")

    def test_case_1_invalid_name_format(self):
        print("\nExecuting Test Case 1: Invalid Name Format")
        self.fill_form({
            "name": "123Invalid",  # Numbers not allowed in name
            "email": "test@example.com",
            "password": "password123",
            "confirm_password": "password123",
            "phone": "1234567890",
            "address": "Test Address"
        })
        self.driver.find_element(By.XPATH, "//input[@type='submit']").click()
        # Check for error message
        error_msg = self.driver.find_element(By.ID, "nameError").text
        self.assertNotEqual(error_msg, "")
        print("Test Case 1 completed: Invalid name format tested")

    def test_case_2_password_mismatch(self):
        print("\nExecuting Test Case 2: Password Mismatch")
        self.fill_form({
            "name": "Test User",
            "email": "test@example.com",
            "password": "password123",
            "confirm_password": "password456",  # Different password
            "phone": "1234567890",
            "address": "Test Address"
        })
        self.driver.find_element(By.XPATH, "//input[@type='submit']").click()
        error_msg = self.driver.find_element(By.ID, "confirmPasswordError").text
        self.assertNotEqual(error_msg, "")
        print("Test Case 2 completed: Password mismatch tested")

    def test_case_3_invalid_phone(self):
        print("\nExecuting Test Case 3: Invalid Phone Number")
        self.fill_form({
            "name": "Test_User",
            "email": "test@example.com",
            "password": "password123",
            "confirm_password": "password123",
            "phone": "1",  # Invalid phone number
            "address": "Test Address"
        })
        self.driver.find_element(By.XPATH, "//input[@type='submit']").click()
        error_msg = self.driver.find_element(By.ID, "phoneError").text
        self.assertNotEqual(error_msg, "")
        print("Test Case 3 completed: Invalid phone number tested")

    def test_case_4_valid_signup(self):
        print("\nExecuting Test Case 4: Valid Signup")
        self.fill_form({
            "name": "Test User",
            "email": "nuste@example.com",
            "password": "Password123!",
            "confirm_password": "Password123!",
            "phone": "1234567890",
            "address": "123 Test Street, City"
        })
        self.driver.find_element(By.XPATH, "//input[@type='submit']").click()
        
        # Wait for successful signup (adjust based on your redirect)
        time.sleep(2)
        # Assert we're no longer on the signup page
        self.assertNotEqual(self.driver.current_url, "http://127.0.0.1:8000/signup/")
        print("Test Case 4 completed: Valid signup tested")

    def fill_form(self, data):
        """Helper method to fill the signup form"""
        self.driver.find_element(By.ID, "name").send_keys(data["name"])
        self.driver.find_element(By.ID, "email").send_keys(data["email"])
        self.driver.find_element(By.ID, "password").send_keys(data["password"])
        self.driver.find_element(By.ID, "confirmPassword").send_keys(data["confirm_password"])
        self.driver.find_element(By.ID, "phone").send_keys(data["phone"])
        self.driver.find_element(By.ID, "address").send_keys(data["address"])

    def wait_for_sweet_alert(self):
        """Helper method to wait for SweetAlert"""
        WebDriverWait(self.driver, 10).until(
            EC.presence_of_element_located((By.CLASS_NAME, "swal2-popup"))
        )

    def tearDown(self):
        print("\nCleaning up: Closing browser")
        self.driver.quit()

if __name__ == "__main__":
    unittest.main()
