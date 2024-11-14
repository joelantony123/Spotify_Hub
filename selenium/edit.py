from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import unittest

class TestEditProfile(unittest.TestCase):
    def setUp(self):
        self.driver = webdriver.Chrome()
        self.driver.maximize_window()
        self.wait = WebDriverWait(self.driver, 10)
        self.login()

    def login(self):
        self.driver.get("http://127.0.0.1:8000/login/")
        self.driver.find_element(By.NAME, "email").send_keys("anands2025@mca.ajce.in")
        self.driver.find_element(By.NAME, "password").send_keys("anand123*")
        self.driver.find_element(By.XPATH, "//input[@type='submit']").click()
        self.wait.until(EC.presence_of_element_located((By.ID, "profileDropdown")))

    def navigate_to_edit_profile(self):
        self.wait.until(EC.element_to_be_clickable((By.ID, "profileDropdown"))).click()
        self.wait.until(EC.element_to_be_clickable(
            (By.XPATH, "//a[contains(text(), 'Edit Profile')]")
        )).click()
        self.wait.until(EC.presence_of_element_located((By.ID, "editProfileForm")))

    def test_update_profile(self):
        self.navigate_to_edit_profile()
        
        # Update profile information
        fields = {
            "name": "Updated Test Name",
            "phone": "+911234567890",
            "address": "123 Updated Test Address"
        }
        
        for field_id, value in fields.items():
            element = self.driver.find_element(By.ID, field_id)
            element.clear()
            element.send_keys(value)

        self.driver.find_element(By.CLASS_NAME, "btn-submit").click()
        self.wait.until(EC.presence_of_element_located((By.CLASS_NAME, "success-message")))

    def test_invalid_inputs(self):
        self.navigate_to_edit_profile()
        
        # Test invalid phone
        phone_field = self.driver.find_element(By.ID, "phone")
        phone_field.clear()
        phone_field.send_keys("invalid")
        
        self.driver.find_element(By.CLASS_NAME, "btn-submit").click()
        error = self.wait.until(EC.presence_of_element_located((By.ID, "phoneError")))
        self.assertNotEqual(error.text, "")

    def tearDown(self):
        self.driver.quit()

if __name__ == "__main__":
    unittest.main()