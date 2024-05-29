import sys, os, subprocess
from PyQt5.QtWidgets import QDialog, QApplication, QFileDialog, QMessageBox
from seedUI import Ui_Dialog

class SeedDialog(QDialog):
    def __init__(self):

        super().__init__()
        self.ui=Ui_Dialog()
        self.ui.setupUi(self)
        self.show()
        
        self.ui.radio_encrypt.setChecked(True)
        self.update_labels()

        self.ui.btn_find_file.clicked.connect(self.find_file)
        self.ui.radio_encrypt.toggled.connect(self.update_labels)
        self.ui.radio_decrypt.toggled.connect(self.update_labels)
        self.ui.btn_finish.clicked.connect(QApplication.instance().quit)
        self.ui.btn_play.clicked.connect(self.run_seed)

        self.ui.txt_key.textChanged.connect(self.validate_key_input)
        self.ui.txt_key2.textChanged.connect(self.validate_key_input)

    def validate_key_input(self):
        text_editors = [self.ui.txt_key, self.ui.txt_key2]
        for editor in text_editors:
            cursor_position = editor.textCursor().position()
            text = editor.toPlainText()
            # 알파벳과 숫자만 입력, 16자로 제한
            new_text = ''.join(filter(str.isascii, text))[:16]
            if text != new_text:
                editor.setPlainText(new_text)
                cursor = editor.textCursor()
                cursor.setPosition(cursor_position)
                editor.setTextCursor(cursor)

    def find_file(self):
        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly
        file_name, _ = QFileDialog.getOpenFileName(self, "Open File", "", "All Files (*);;Text Files (*.txt)", options=options)
        if file_name:
            if self.ui.radio_encrypt.isChecked():
                self.ui.txt_before_file.setText(file_name)
                # 자동으로 암호파일 경로 설정
                dir_name, base_name = os.path.split(file_name)
                encrypt_mode = self.ui.combo_mode.currentText()
                encrypted_file_name = f"encrypted_{encrypt_mode}_{base_name}"
                encrypted_file_path = os.path.join(dir_name, encrypted_file_name)
                self.ui.txt_after_file.setText(encrypted_file_path)
            elif self.ui.radio_decrypt.isChecked():
                dir_name, base_name = os.path.split(file_name)
                if not base_name.startswith("encrypted_"):
                    QMessageBox.warning(self, "Invalid File", "파일 이름이 'encrypted_'로 시작해야 합니다.")
                    return 
                self.ui.txt_before_file.setText(file_name)
                decrypted_file_name = f"decrypted_{base_name[len('encrypted_'):]}"
                decrypted_file_path = os.path.join(dir_name, decrypted_file_name)
                self.ui.txt_after_file.setText(decrypted_file_path)

    def run_seed(self):
        key = self.ui.txt_key.toPlainText()
        key_confirm = self.ui.txt_key2.toPlainText()
        
        if key != key_confirm:
            QMessageBox.warning(self, "Key Mismatch", "입력한 키가 일치하지 않습니다.")
            return

        input_file_path = self.ui.txt_before_file.toPlainText()
        output_file_path = self.ui.txt_after_file.toPlainText()
        mode = "0" if self.ui.radio_encrypt.isChecked() else "1"
        encrypt_mode = self.ui.combo_mode.currentText()

        classpath = f"/Users/choijonghak/개인파일/동의대/정보보호/SEED/mode/{encrypt_mode}"
        encryptmode = f"KISA_SEED_{encrypt_mode}"
        print(key, input_file_path, output_file_path, mode, classpath, encryptmode)
        self.run_java_program(key, input_file_path, output_file_path, mode, classpath, encryptmode)

                
    def run_java_program(self, key, input_file_path, output_file_path, mode, classpath, encryptmode):
        command = ["java", "-cp", classpath, encryptmode, key, input_file_path, output_file_path, mode]
        result = subprocess.run(command, capture_output=True, text=True)
        print(result.stdout)

    def update_labels(self):
        if self.ui.radio_encrypt.isChecked():
            self.ui.label_7.setText("원본파일")
            self.ui.label_file.setText("암호파일")
            
        elif self.ui.radio_decrypt.isChecked():
            self.ui.label_7.setText("암호파일")
            self.ui.label_file.setText("복호파일")
        self.ui.txt_before_file.clear()
        self.ui.txt_after_file.clear()

if __name__=='__main__':

    app=QApplication(sys.argv)
    appwindow =SeedDialog()
    appwindow.show()
    sys.exit(app.exec_())