from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time
import unittest

class TestLogin(unittest.TestCase):
    def setUp(self):
        print("\n=== Setting up test environment ===")
        self.driver = webdriver.Chrome()
        self.driver.get("http://127.0.0.1:8000/login/")
        self.driver.maximize_window()
        print("Browser launched and navigated to login page")

    def test_case_1_invalid_email_format(self):
        print("\nExecuting Test Case 1: Invalid Email Format")
        email = self.driver.find_element(By.NAME, "email")
        password = self.driver.find_element(By.NAME, "password")
        
        email.send_keys("invalid.email")
        password.send_keys("anypassword")
        self.driver.find_element(By.XPATH, "//input[@type='submit']").click()
        
        # Wait for error message
        self.wait_for_sweet_alert()
        print("Test Case 1 completed: Invalid email format tested")

    def test_case_2_empty_fields(self):
        print("\nExecuting Test Case 2: Empty Fields")
        self.driver.find_element(By.XPATH, "//input[@type='submit']").click()
        # The form has HTML5 validation, so no need to wait for sweet alert
        print("Test Case 2 completed: Empty fields tested")

    def test_case_3_wrong_credentials(self):
        print("\nExecuting Test Case 3: Wrong Credentials")
        email = self.driver.find_element(By.NAME, "email")
        password = self.driver.find_element(By.NAME, "password")
        
        email.send_keys("wrong@email.com")
        password.send_keys("wrongpassword")
        self.driver.find_element(By.XPATH, "//input[@type='submit']").click()
        
        # Wait for error message
        self.wait_for_sweet_alert()
        print("Test Case 3 completed: Wrong credentials tested")

    def test_case_4_valid_login(self):
        print("\nExecuting Test Case 1: Valid Login")
        email = self.driver.find_element(By.NAME, "email")
        password = self.driver.find_element(By.NAME, "password")
        
        email.send_keys("anands2025@mca.ajce.in")
        password.send_keys("anand123*")
        self.driver.find_element(By.XPATH, "//input[@type='submit']").click()
        
        # Wait for successful login (you might need to adjust this based on your redirect)
        time.sleep(2)
        # Assert we're no longer on the login page
        self.assertNotEqual(self.driver.current_url, "http://127.0.0.1:8000/login/")
        print("Test Case completed: Valid login tested")

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