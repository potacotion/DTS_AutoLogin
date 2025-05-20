# test_python_encrypt.py
import main  # Assumes campus_login.py is in the same directory or PYTHONPATH


def run_python_encryption_test(text_to_encrypt, exponent_hex, modulus_hex):
    print("--- Python Encryption Test ---")
    print(f"Input Text: '{text_to_encrypt}'")
    print(f"Exponent (hex): {exponent_hex}")
    print(f"Modulus (hex): {modulus_hex}")
    print("-" * 30)

    # --- Ensure detailed prints are added inside campus_login.encrypt_password ---
    # This function will call the version from campus_login.py, which needs modification.
    # Example of prints to add in campus_login.encrypt_password:
    # print(f"PY: js_chunk_size = {js_chunk_size}")
    # print(f"PY: s_char_codes (padded) = {s_char_codes}")
    # Inside the loop for each block:
    #   print(f"PY: ---- Block {i // js_chunk_size} ----")
    #   print(f"PY: current_chunk_char_codes = {current_chunk_char_codes}")
    #   # Inside the inner loop for digits:
    #   #   print(f"PY: digit_val[{j_idx}] = {digit_val}")
    #   print(f"PY: block_int_val = {block_int_val}")
    #   print(f"PY: encrypted_block_int = {encrypted_block_int}")
    #   # Inside _python_bi_to_hex(encrypted_block_int):
    #   #   print(f"PY_BI_TO_HEX: input = {big_int_val}")
    #   #   print(f"PY_BI_TO_HEX: digits_list (LSW first) = {digits_list}")
    #   #   Inside loop for each digit in _python_bi_to_hex:
    #   #     print(f"PY_BI_TO_HEX: processing digit {digits_list[i_rev]} -> hex {_python_digit_to_hex(digits_list[i_rev])}")
    #   print(f"PY: hex_text_for_block = {hex_text}")
    # print(f"PY: encrypted_hex_parts before join = {encrypted_hex_parts}")

    encrypted_result = main.encrypt_password(text_to_encrypt, exponent_hex, modulus_hex)

    print("-" * 30)
    print(f"Final Encrypted Result (Python): '{encrypted_result}'")
    print("--- End Python Test ---\n")
    return encrypted_result


if __name__ == "__main__":
    # --- Test Case ---
    # IMPORTANT: Use a very short, simple string for initial testing.
    # Ensure this matches the 'testText' in test_js_encrypt.html.
    test_text = "1"
    # test_text = "ab"
    # For more complex tests later, ensure the JS side constructs the identical reversed string:
    # python_equivalent_of_js_input = ("test_password" + ">" + "test_mac")[::-1]
    # test_text = python_equivalent_of_js_input

    # CRITICAL: Replace with actual exponent and modulus from a real ePortal session.
    # These are placeholders and WILL NOT WORK for your specific portal.
    # Get these from a browser's network inspector when page_info is fetched.
    test_exponent_hex = "010001"  # Common RSA exponent (65537 decimal), likely correct
    test_modulus_hex = "94dd2a8675fb779e6b9f7103698634cd400f27a154afa67af6166a43fc26417222a79506d34cacc7641946abda1785b7acf9910ad6a0978c91ec84d40b71d2891379af19ffb333e7517e390bd26ac312fe940c340466b4a5d4af1d65c3b5944078f96a1a51a5a53e4bc302818b7c9f63c4a1b07bd7d874cef1c3d4b2f5eb7871"  # e.g., "b399a231...0001"

    if "YOUR_ACTUAL_MODULUS_HEX" in test_modulus_hex:
        print(
            "ERROR: Please replace 'YOUR_ACTUAL_MODULUS_HEX_FROM_PAGE_INFO_HERE' in test_python_encrypt.py with a real modulus.")
    else:
        print(
            "Reminder: Ensure you've added detailed print statements inside campus_login.py's encrypt_password function as commented above.")
        run_python_encryption_test(test_text, test_exponent_hex, test_modulus_hex)
