import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.applet.Applet;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Base64;

public class AESApplet extends Applet implements ActionListener {

    private TextField inputField;
    private TextField keyField;
    private Button encryptButton;
    private Button decryptButton;
    private TextArea outputArea;

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";

    public void init() {
        setLayout(new BorderLayout());

        Panel inputPanel = new Panel(new GridLayout(3, 2));
        inputPanel.add(new Label("Input:"));
        inputField = new TextField();
        inputPanel.add(inputField);
        inputPanel.add(new Label("Key:"));
        keyField = new TextField();
        inputPanel.add(keyField);
        encryptButton = new Button("Encrypt");
        encryptButton.addActionListener(this);
        inputPanel.add(encryptButton);
        decryptButton = new Button("Decrypt");
        decryptButton.addActionListener(this);
        inputPanel.add(decryptButton);
        add(inputPanel, BorderLayout.NORTH);

        outputArea = new TextArea();
        outputArea.setEditable(false);
        add(outputArea, BorderLayout.CENTER);

        setSize(400, 300);
    }

    public void actionPerformed(ActionEvent e) {
        String key = keyField.getText();
        String input = inputField.getText();

        try {
            if (e.getSource() == encryptButton) {
                String encryptedText = encrypt(key, input);
                outputArea.setText("Encrypted Text:\n" + encryptedText);
            } else if (e.getSource() == decryptButton) {
                String decryptedText = decrypt(key, input);
                outputArea.setText("Decrypted Text:\n" + decryptedText);
            }
        } catch (Exception ex) {
            outputArea.setText("Error: " + ex.getMessage());
        }
    }

    private String encrypt(String key, String input) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(input.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private String decrypt(String key, String encryptedText) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes);
    }
}
/*<applet code = "AESApplet.class" width = "1000" height = "1000">
</applet>
*/