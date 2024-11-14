from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.action_chains import ActionChains
import unittest
import time

class TestCartFunctionality(unittest.TestCase):
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

    def test_add_to_cart(self):
        try:
            # Scroll down to products section
            self.driver.execute_script("window.scrollBy(0, 800)")
            time.sleep(2)

            # Find and click the first Add to Cart button
            add_to_cart_button = self.wait.until(
                EC.element_to_be_clickable((By.CLASS_NAME, "add-to-cart"))
            )
            self.driver.execute_script("arguments[0].click();", add_to_cart_button)
            
            # Wait for and handle the alert
            try:
                alert = self.wait.until(EC.alert_is_present())
                alert_text = alert.text
                alert.accept()
                print(f"Alert handled: {alert_text}")
            except:
                print("No alert present")

            # Scroll back to top
            self.driver.execute_script("window.scrollTo(0, 0)")
            time.sleep(1)

            # Click cart icon to navigate to cart page
            cart_icon = self.wait.until(
                EC.element_to_be_clickable((By.CLASS_NAME, "cart_link"))
            )
            self.driver.execute_script("arguments[0].click();", cart_icon)

            # Verify we're on cart page by checking for cart items
            self.wait.until(EC.presence_of_element_located((By.CLASS_NAME, "cart_item")))
            print("Successfully added product to cart and navigated to cart page")

        except Exception as e:
            print(f"Add to cart test failed: {str(e)}")
            self.driver.save_screenshot("cart_error.png")
            raise

    def test_cart_quantity_update(self):
        try:
            # First add item to cart
            self.test_add_to_cart()

            # Find quantity input
            quantity_input = self.wait.until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "input[type='number']"))
            )
            
            # Update quantity
            quantity_input.clear()
            quantity_input.send_keys("2")
            time.sleep(1)  # Wait for quantity update

            print("Successfully updated cart quantity")

        except Exception as e:
            print(f"Cart quantity update test failed: {str(e)}")
            self.driver.save_screenshot("quantity_update_error.png")
            raise

    def tearDown(self):
        if self.driver:
            self.driver.quit()

if __name__ == "__main__":
    unittest.main()