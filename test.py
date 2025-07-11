import os
import json
import string
import pytest
import tempfile
from unittest.mock import patch, MagicMock
from encryptor import Single_File_Encryptor, MASTER_PASSWORD_FILE
from decryptor import Single_File_Decryptor
from xml_logging import XML_Logger

# Test Fixtures
@pytest.fixture
def mock_logger():
    logger = MagicMock(spec=XML_Logger)
    logger.base_dir = tempfile.mkdtemp()
    return logger

@pytest.fixture
def test_config():
    return {
        "File_To_Encrypt": "test.txt",
        "Minimum_Master_Password_Length": 12,
        "Password_Storage_File": "passwords.json",
        "Buffer_Size": 65536,
        "Master_Password_File": MASTER_PASSWORD_FILE
    }

@pytest.fixture
def test_file():
    # Create a temporary test file
    fd, path = tempfile.mkstemp(suffix='.txt')
    with os.fdopen(fd, 'w') as tmp:
        tmp.write("This is a test file content")
    yield path
    # Cleanup
    if os.path.exists(path):
        os.remove(path)
    if os.path.exists(path + '.aes'):
        os.remove(path + '.aes')

@pytest.fixture
def strong_password():
    return "ValidPass123!"

# Tests for Password Validation
def test_password_validation(strong_password):
    from main import _verify_password
    assert _verify_password(strong_password, 12) is True
    assert _verify_password("short", 12) is False
    assert _verify_password("nouppercase123!", 12) is False
    assert _verify_password("NOLOWERCASE123!", 12) is False
    assert _verify_password("NoNumbersHere!", 12) is False
    assert _verify_password("MissingSpecial123", 12) is False

# Tests for Single_File_Encryptor
def test_encryptor_init(mock_logger, strong_password):
    encryptor = Single_File_Encryptor(
        master_password=strong_password,
        password_storage_file="passwords.json",
        logger=mock_logger
    )
    assert isinstance(encryptor, Single_File_Encryptor)
    assert encryptor.master_password == strong_password

def test_generate_strong_password(mock_logger, strong_password):
    encryptor = Single_File_Encryptor(
        master_password=strong_password,
        password_storage_file="passwords.json",
        logger=mock_logger
    )
    password = encryptor.generate_strong_password(15)
    assert len(password) == 15
    assert any(c.isupper() for c in password)
    assert any(c.islower() for c in password)
    assert any(c.isdigit() for c in password)
    assert any(c in string.punctuation for c in password)

def test_encrypt_file(mock_logger, test_file, strong_password):
    encryptor = Single_File_Encryptor(
        master_password=strong_password,
        password_storage_file="passwords.json",
        logger=mock_logger
    )
    
    # Mock the file operations to avoid actual encryption in unit tests
    with patch.object(encryptor, '_encrypt_data_file'), \
         patch('pyAesCrypt.encryptStream'), \
         patch.object(encryptor, 'save_encryption_data', return_value=True):
        
        result = encryptor.encrypt_file(test_file)
        assert result is True
        mock_logger.log_to_xml.assert_not_called()

# Tests for Single_File_Decryptor
def test_decryptor_init(mock_logger, strong_password):
    decryptor = Single_File_Decryptor(
        master_password=strong_password,
        password_storage_file="passwords.json",
        logger=mock_logger
    )
    assert isinstance(decryptor, Single_File_Decryptor)
    assert decryptor.master_password == strong_password

def test_decrypt_file(mock_logger, test_file, strong_password):
    # First create an encrypted file (in-memory)
    encrypted_file = test_file + '.aes'
    
    decryptor = Single_File_Decryptor(
        master_password=strong_password,
        password_storage_file="passwords.json",
        logger=mock_logger
    )
    
    # Mock the file operations to avoid actual decryption in unit tests
    with patch.object(decryptor, '_decrypt_data_file'), \
         patch('pyAesCrypt.decryptStream'), \
         patch.object(decryptor, 'save_encryption_data', return_value=True), \
         patch('builtins.open', MagicMock()):
        
        # Mock the password storage content
        mock_passwords = {encrypted_file: "testpassword123!"}
        with patch('json.load', return_value=mock_passwords):
            result = decryptor.decrypt_file(encrypted_file)
            assert result is True
            mock_logger.log_to_xml.assert_not_called()

# Integration Test
def test_encrypt_decrypt_cycle(mock_logger, test_file, strong_password):
    # Setup
    password_file = os.path.join(os.path.dirname(test_file), "passwords.json")
    
    # Encrypt the file
    encryptor = Single_File_Encryptor(
        master_password=strong_password,
        password_storage_file=password_file,
        logger=mock_logger,
        password_length=32
    )
    
    # Mock the actual encryption stream
    with patch('pyAesCrypt.encryptStream'), \
         patch.object(encryptor, 'save_encryption_data', return_value=True):
        encrypt_result = encryptor.encrypt_file(test_file)
        assert encrypt_result is True
    
    # Decrypt the file
    decryptor = Single_File_Decryptor(
        master_password=strong_password,
        password_storage_file=password_file,
        logger=mock_logger
    )
    
    # Mock the decryption and password retrieval
    with patch('pyAesCrypt.decryptStream'), \
         patch.object(decryptor, 'save_encryption_data', return_value=True), \
         patch('builtins.open', MagicMock()):
        
        # Mock the password storage content
        mock_passwords = {test_file + '.aes': "testpassword123!"}
        with patch('json.load', return_value=mock_passwords):
            decrypt_result = decryptor.decrypt_file(test_file + '.aes')
            assert decrypt_result is True

# Test Error Handling
def test_encrypt_invalid_file(mock_logger, strong_password):
    encryptor = Single_File_Encryptor(
        master_password=strong_password,
        password_storage_file="passwords.json",
        logger=mock_logger
    )
    
    result = encryptor.encrypt_file("nonexistent.txt")
    assert result is False
    mock_logger.log_to_xml.assert_called()

def test_decrypt_invalid_file(mock_logger, strong_password):
    decryptor = Single_File_Decryptor(
        master_password=strong_password,
        password_storage_file="passwords.json",
        logger=mock_logger
    )
    
    result = decryptor.decrypt_file("invalidfile.txt")
    assert result is False
    mock_logger.log_to_xml.assert_called()

# Cleanup
def teardown_module(module):
    # Clean up any test files
    if os.path.exists("passwords.json"):
        os.remove("passwords.json")
    if os.path.exists("passwords.json.aes"):
        os.remove("passwords.json.aes")
    if os.path.exists(MASTER_PASSWORD_FILE):
        os.remove(MASTER_PASSWORD_FILE)