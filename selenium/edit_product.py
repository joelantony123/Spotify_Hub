


from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import unittest
import time

class TestDeleteFromCart(unittest.TestCase):
    def setUp(self):
        self.driver = webdriver.Chrome()
        self.driver.maximize_window()
        self.wait = WebDriverWait(self.driver, 10)
        self.login()

    def login(self):
        try:
            self.driver.get("http://127.0.0.1:8000/login/")
            self.driver.find_element(By.NAME, "email").send_keys("anands2025@mca.ajce.in")
            self.driver.find_element(By.NAME, "password").send_keys("anand123*")
            self.driver.find_element(By.XPATH, "//input[@type='submit']").click()
            self.wait.until(EC.presence_of_element_located((By.CLASS_NAME, "navbar")))
        except Exception as e:
            print(f"Login failed: {str(e)}")
            raise

    def test_delete_from_cart(self):
        try:
            # Click cart icon to navigate to cart
            cart_link = self.wait.until(
                EC.element_to_be_clickable((By.CLASS_NAME, "cart_link"))
            )
            self.driver.execute_script("arguments[0].click();", cart_link)
            time.sleep(2)

            # Find and click the remove button
            remove_button = self.wait.until(
                EC.element_to_be_clickable((By.CLASS_NAME, "btn-remove"))
            )
            self.driver.execute_script("arguments[0].click();", remove_button)

            # Handle the confirmation alert
            alert = self.wait.until(EC.alert_is_present())
            alert.accept()
            time.sleep(2)

            print("Successfully removed item from cart")

        except Exception as e:
            print(f"Delete from cart test failed: {str(e)}")
            self.driver.save_screenshot("delete_cart_error.png")
            raise

    def tearDown(self):
        if self.driver:
            self.driver.quit()

if __name__ == "__main__":
    unittest.main()