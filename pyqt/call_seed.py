import subprocess

def generate_key():
    return "your_secret_key"

def run_java_program(key, input_file_path, output_file_path, mode, classpath, encryptmode):
    command = ["java", "-cp", classpath, encryptmode, key, input_file_path, output_file_path, mode]
    result = subprocess.run(command, capture_output=True, text=True)
    print(result.stdout)

if __name__ == "__main__":
    key = generate_key()
    default_classpath = "/Users/choijonghak/개인파일/동의대/정보보호/SEED/mode/"
    default_encryptmode = "KISA_SEED_"
    
    classpath = default_classpath + "ECB"
    encryptmode = default_encryptmode + "ECB"

    input_file_path = "/Users/choijonghak/개인파일/동의대/정보보호/SEED/input.txt"
    output_file_path = "/Users/choijonghak/개인파일/동의대/정보보호/SEED/encrypted_input.txt"
    
    run_java_program(key, input_file_path, output_file_path, "0", classpath, encryptmode)
