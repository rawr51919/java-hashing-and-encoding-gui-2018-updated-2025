// Logger imports
import java.util.logging.Level;
import java.util.logging.Logger;
// I/O imports
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.FileInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
// AWT graphics imports
import java.awt.Font;
import java.awt.Color;
import java.awt.Insets;
import java.awt.Dimension;
import java.awt.BorderLayout;
// AWT event imports
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
// Swing graphics imports
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JFrame;
import javax.swing.JButton;
import javax.swing.UIManager;
import javax.swing.ImageIcon;
import javax.swing.JTextArea;
import javax.swing.JCheckBox;
import javax.swing.JScrollPane;
import javax.swing.JOptionPane;
import javax.swing.JFileChooser;
// Swing threading import (allows the GUI to run in a thread)
import javax.swing.SwingUtilities;
// Hash class imports
import org.kc7bfi.jflac.util.CRC8;
import godlikeblock.util.CRC16;
import java.util.zip.CRC32;
import java.util.zip.Adler32;
import byte_transforms.CRC64;
import fr.cryptohash.RIPEMD;
import fr.cryptohash.RIPEMD128;
import fr.cryptohash.RIPEMD160;
import fr.cryptohash.SHA0;
import fr.cryptohash.Tiger;
import fr.cryptohash.Tiger2;
import fr.cryptohash.Whirlpool0;
import fr.cryptohash.Whirlpool1;
import fr.cryptohash.Whirlpool;
// MD2-SHA512 hash imports
import org.apache.commons.codec.digest.DigestUtils;
import jcifs.util.MD4;
// XYZ hash import (the algorithm of said hash is from https://docstore.mik.ua/orelly/java-ent/security/ch09_03.htm)
import com.xyz.XYZMessageDigest;
// Misc imports (for outputting the MD4 and XYZ hashes properly)
import jcifs.util.Hexdump;

// define class
public class CRhashingGUI extends JPanel implements ActionListener {
	private static final Logger logger = Logger.getLogger(CRhashingGUI.class.getName());
	// declaring our variables (Strings, GUI elements, even the serialVersionUID)
	private static final long serialVersionUID = 999L;
	protected static String crc8string;
	protected static String crc16string;
	protected static String crc32string;
	protected static String adler32string;
	protected static String crc64string;
	protected static String ripemdstring;
	protected static String ripemd128string;
	protected static String ripemd160string;
	protected static String tigerstring;
	protected static String tiger2string;
	protected static String whirlpool0string;
	protected static String whirlpool1string;
	protected static String whirlpoolstring;
	protected static String xyzstring;
	protected static String md2string;
	protected static String md4string;
	protected static String md5string;
	protected static String sha0string;
	protected static String sha1string;
	protected static String sha224string;
	protected static String sha256string;
	protected static String sha384string;
	protected static String sha512string;
	protected File file;
	protected static File outputfile;
	JButton openButton;
	JButton stringButton;
	JButton saveButton;
	JButton creditsButton;
	JButton clearButton;
	// create the log, file chooser, and checkboxes
	public static final JTextArea log = new JTextArea(5, 20);
	static JFileChooser fc = new JFileChooser();
	static JCheckBox checkbox = new JCheckBox("Show hidden files in file chooser");
	public static final SHA0 e0 = new SHA0();
	public static final MD4 e4 = new MD4();
	public static final CRC16 e16 = new CRC16();
	public static final CRC32 e32 = new CRC32();
	public static final CRC64 e64 = new CRC64();
	public static final Adler32 ae32 = new Adler32();
	public static final RIPEMD ermd = new RIPEMD();
	public static final RIPEMD128 e128 = new RIPEMD128();
	public static final RIPEMD160 e160 = new RIPEMD160();
	public static final Tiger et = new Tiger();
	public static final Tiger2 et2 = new Tiger2();
	public static final Whirlpool0 ew1 = new Whirlpool0();
	public static final Whirlpool1 ew2 = new Whirlpool1();
	public static final Whirlpool ew = new Whirlpool();
	public static final XYZMessageDigest exyz = new XYZMessageDigest();

	public static void main(String[] args) {
		SwingUtilities.invokeLater(() -> {
			try {
				UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
			} catch (Exception f) {
				f.printStackTrace();
			}
			createAndShowGUI();
		});
	}

	private static void createAndShowGUI() {
		JFrame frame = new JFrame("Hashing GUI");
		frame.setDefaultCloseOperation(3); // JFrame.EXIT_ON_CLOSE
		frame.add(new CRhashingGUI());
		frame.setPreferredSize(new Dimension(1250, 630)); // set the JFrame size so that way you don't have to resize it
															// every time you load the GUI
		frame.setFont(new Font("Lucida", Font.PLAIN, 20));
		frame.pack();
		frame.setVisible(true);
	}

	public CRhashingGUI() {
		super(new BorderLayout());
		// setting options for the log
		log.setMargin(new Insets(5, 5, 5, 5));
		log.setEditable(false);
		log.setFont(new Font("Lucida", Font.PLAIN, 14));
		JScrollPane logScrollPane = new JScrollPane(log);
		// create buttons and import icons
		openButton = new JButton("Open a File...", createImageIcon("images/Open16.gif"));
		stringButton = new JButton("Hash a String...");
		saveButton = new JButton("Save a File's Hashes As...", createImageIcon("images/Save16.gif"));
		creditsButton = new JButton("Credits...");
		clearButton = new JButton("Clear Log...");
		// set up ActionListeners
		openButton.addActionListener(this);
		stringButton.addActionListener(this);
		saveButton.addActionListener(this);
		creditsButton.addActionListener(this);
		clearButton.addActionListener(this);
		// add the button panels and format them correctly
		JPanel topPanel = new JPanel();
		JPanel bottomPanel = new JPanel();
		topPanel.add(openButton);
		topPanel.add(stringButton);
		topPanel.add(saveButton);
		topPanel.add(creditsButton);
		bottomPanel.add(checkbox);
		bottomPanel.add(clearButton);
		add(topPanel, BorderLayout.PAGE_START);
		add(logScrollPane, BorderLayout.CENTER);
		add(bottomPanel, BorderLayout.PAGE_END);
	}

	private void handleOpenButton() {
		int returnVal = fc.showOpenDialog(this);
		if (returnVal != JFileChooser.APPROVE_OPTION) {
			log.append("Open command cancelled by user.\n");
			log.setCaretPosition(log.getDocument().getLength());
			return;
		}

		try {
			file = fc.getSelectedFile();
			try (FileInputStream filestream = new FileInputStream(file)) {
				log.append("Opening " + file.getName() + "...\n");
				log.append("Open successful!\n");
				getHashes(filestream);
				log.append("The hashes/encoded strings of " + file.getName() + " are:\n");
				logHashes();
			}
		} catch (FileNotFoundException e) {
			log.append("Error: File not found.\n");
		} catch (IOException e) {
			logger.severe("Error reading file: " + e.getMessage());
		}
		log.setCaretPosition(log.getDocument().getLength());
	}

	private void handleStringButton() {
		String string = JOptionPane.showInputDialog("Enter a string to be hashed and encoded here...");
		if (string == null)
			return;

		getStringHashes(string);
		log.append("The hashes/encoded strings of " + string + " are:\n");
		logHashes();
	}

	private void handleSaveButton() {
		int returnVal = fc.showSaveDialog(this);
		if (returnVal != JFileChooser.APPROVE_OPTION)
			return;

		try {
			final String saveName;
			if (file != null && file.exists()) {
				saveName = file.getAbsolutePath().replaceAll("\\.[^.]*$", "");
			} else {
				saveName = "Generated";
			}

			try (FileWriter writer = new FileWriter(saveName + " hashes.txt")) {
				log.write(writer);
			}
			log.append("File successfully saved!\n");
		} catch (IOException e) {
			logger.severe("Cannot save text to file: " + e.getMessage());
		}
	}

	private void showCredits() {
		JFrame creditsframe = new JFrame("Credits");
		JLabel creditslabel = new JLabel(
				"<html><div style='text-align: center'>Credits:<br>" +
						"This GUI: rawr51919<br>" +
						"Based on the FileChooserDemo2 project (https://docs.oracle.com/javase/tutorial/uiswing/examples/components/index.html#FileChooserDemo2)" +
						"Original project part of the Java Swing tutorial on file choosers (https://docs.oracle.com/javase/tutorial/uiswing/components/filechooser.html)" +
						"CRC8 Library: JustFLAC (https://github.com/drogatkin/JustFLAC)<br>" +
						"CRC16 Library: Original code by Taha Paksu (http://www.tahapaksu.com/crc) and ported by Ethan Trithon (https://github.com/ethantrithon)<br>"
						+
						"XYZ Library: Original code by Java Enterprise in a Nutshell, 1st Edition (https://docstore.mik.ua/orelly/java-ent/security/ch09_03.htm)<br>"
						+
						"CRC64 Library: Zach Tellman (https://github.com/ztellman/byte-transforms)<br>" +
						"RIPEMD, RIPEMD128, RIPEMD160, SHA-0, Tiger, Tiger2, Whirlpool 2000/2001/2003 Libraries: Burst Project (https://github.com/BurstProject/pocminer)<br>"
						+
						"MD2, MD5, SHA-1/SHA160, SHA224, SHA256, SHA384, and SHA512 Libraries: Apache Commons (https://commons.apache.org)</html>");

		JPanel creditspanel = new JPanel();
		creditspanel.setBackground(Color.white);
		creditspanel.add(creditslabel);

		creditsframe.add(creditspanel);
		creditsframe.setSize(800, 250);
		creditsframe.setVisible(true);
	}

	public void actionPerformed(ActionEvent e) {
		fc.setFileHidingEnabled(!checkbox.isSelected());

		Object src = e.getSource();

		if (src == clearButton) {
			log.setText(null);
			return;
		}

		if (src == openButton) {
			handleOpenButton();
			return;
		}

		if (src == stringButton) {
			handleStringButton();
			return;
		}

		if (src == saveButton) {
			handleSaveButton();
			return;
		}

		if (src == creditsButton) {
			showCredits();
		}
	}

	private void logHashes() {
		// The full list of hash strings
		log.append("CRC8: " + crc8string + "\n");
		log.append("CRC16: " + crc16string + "\n");
		log.append("CRC32: " + crc32string + "\n");
		log.append("Adler-32: " + adler32string + "\n");
		log.append("XYZ: " + xyzstring + "\n");
		log.append("CRC64: " + crc64string + "\n");
		log.append("MD2: " + md2string + "\n");
		log.append("MD4: " + md4string + "\n");
		log.append("MD5: " + md5string + "\n");
		log.append("RIPEMD: " + ripemdstring + "\n");
		log.append("RIPEMD128: " + ripemd128string + "\n");
		log.append("RIPEMD160: " + ripemd160string + "\n");
		log.append("SHA-0: " + sha0string + "\n");
		log.append("SHA-1/SHA160: " + sha1string + "\n");
		log.append("Tiger: " + tigerstring + "\n");
		log.append("Tiger2: " + tiger2string + "\n");
		log.append("SHA224: " + sha224string + "\n");
		log.append("SHA256: " + sha256string + "\n");
		log.append("SHA384: " + sha384string + "\n");
		log.append("SHA512: " + sha512string + "\n");
		log.append("Whirlpool 2000: " + whirlpool0string + "\n");
		log.append("Whirlpool 2001: " + whirlpool1string + "\n");
		log.append("Whirlpool 2003: " + whirlpoolstring + "\n");
	}

	private static ImageIcon createImageIcon(String path) {
		java.net.URL imgURL = CRencodingGUI.class.getResource(path); // get the icon images
		// if they exist
		if (imgURL != null) {
			return new ImageIcon(imgURL); // display them in the GUI
			// if they don't
		} else {
			if (logger.isLoggable(Level.SEVERE)) {
				logger.severe(String.format("Couldn't find file: %s", path)); // report in the console that they don't
																				// exist
			}
			return null; // display blank images
		}
	}

	private static void getHashes(FileInputStream filestream) {
		ByteArrayOutputStream filebytestream = new ByteArrayOutputStream();
		int byteread;
		byte[] filebytes;
		try {
			filebytes = filestream.readAllBytes();
			while ((byteread = filestream.read(filebytes, 0, filebytes.length)) != -1) {
				filebytestream.write(filebytes, 0, byteread);
			}
			filebytestream.close();
		// if the file suddenly doesn't exist, or if an I/O error occurred
		} catch (IOException e) {
			log.append("Error when creating file input.\n"); // send this error to the log
			e.printStackTrace();
		}
		filebytes = filebytestream.toByteArray();
		// generate the hashes/encoded strings and output them to their respective
		// strings, doing whatever operations are needed to make them display correctly
		int crc8int = CRC8.calc(filebytes, filebytes.length) & 0xff;
		crc8string = Integer.toHexString(crc8int).toUpperCase();
		if (crc8int < 0x10 /* the first number to not have a leading 0 */)
			crc8string = "0" + crc8string;
		int crc16int = e16.update(filebytes);
		crc16string = Integer.toHexString(crc16int).toUpperCase();
		if (crc16int < 0x1000 /* the first number to not have a leading 0 */)
			crc16string = "0" + crc16string;
		e32.update(filebytes);
		long crc32long = e32.getValue();
		crc32string = Long.toHexString(crc32long).toUpperCase();
		if (crc32long < 0x10000000 /* the first number to not have a leading 0 */)
			crc32string = "0" + crc32string;
		ae32.update(filebytes);
		long adler32long = ae32.getValue();
		adler32string = Long.toHexString(adler32long).toUpperCase();
		if (adler32long < 0x10000000 /* the first number to not have a leading 0 */)
			adler32string = "0" + adler32string;
		e64.update(filebytes);
		long crc64long = e64.getValue();
		crc64string = Long.toHexString(crc64long).toUpperCase();
		if (crc64long < 0x1000000000000000L /* the first number to not have a leading 0 */)
			crc64string = "0" + crc64string;
		md2string = DigestUtils.md2Hex(filebytes).toUpperCase();
		e4.engineUpdate(filebytes, 0, filebytes.length);
		byte[] md4hashbytes = e4.engineDigest();
		md4string = Hexdump.toHexString(md4hashbytes, 0, md4hashbytes.length * 2);
		exyz.engineUpdate(filebytes, 0, filebytes.length);
		byte[] xyzhashbytes = exyz.engineDigest();
		xyzstring = Hexdump.toHexString(xyzhashbytes, 0, xyzhashbytes.length * 2);
		md5string = DigestUtils.md5Hex(filebytes).toUpperCase();
		ermd.update(filebytes);
		byte[] ripemdbytes = ermd.digest();
		ripemdstring = Hexdump.toHexString(ripemdbytes, 0, ripemdbytes.length * 2);
		e128.update(filebytes);
		byte[] ripemd128bytes = e128.digest();
		ripemd128string = Hexdump.toHexString(ripemd128bytes, 0, ripemd128bytes.length * 2);
		e160.update(filebytes);
		byte[] ripemd160bytes = e160.digest();
		ripemd160string = Hexdump.toHexString(ripemd160bytes, 0, ripemd160bytes.length * 2);
		e0.update(filebytes);
		byte[] sha0bytes = e0.digest();
		sha0string = Hexdump.toHexString(sha0bytes, 0, sha0bytes.length * 2);
		sha1string = DigestUtils.sha1Hex(filebytes).toUpperCase();
		sha224string = DigestUtils.sha224Hex(filebytes).toUpperCase();
		sha256string = DigestUtils.sha256Hex(filebytes).toUpperCase();
		sha384string = DigestUtils.sha384Hex(filebytes).toUpperCase();
		sha512string = DigestUtils.sha512Hex(filebytes).toUpperCase();
		et.update(filebytes);
		byte[] tigerbytes = et.digest();
		tigerstring = Hexdump.toHexString(tigerbytes, 0, tigerbytes.length * 2);
		et2.update(filebytes);
		byte[] tiger2bytes = et2.digest();
		tiger2string = Hexdump.toHexString(tiger2bytes, 0, tiger2bytes.length * 2);
		ew1.update(filebytes);
		byte[] whirlpool0bytes = ew1.digest();
		whirlpool0string = Hexdump.toHexString(whirlpool0bytes, 0, whirlpool0bytes.length * 2);
		ew2.update(filebytes);
		byte[] whirlpool1bytes = ew2.digest();
		whirlpool1string = Hexdump.toHexString(whirlpool1bytes, 0, whirlpool1bytes.length * 2);
		ew.update(filebytes);
		byte[] whirlpoolbytes = ew.digest();
		whirlpoolstring = Hexdump.toHexString(whirlpoolbytes, 0, whirlpoolbytes.length * 2);
	}

	public static void getStringHashes(String string) {
		byte[] stringbytes = string.getBytes();
		int crc8int = CRC8.calc(stringbytes, stringbytes.length) & 0xff;
		crc8string = Integer.toHexString(crc8int).toUpperCase();
		if (crc8int < 0x10 /* the first number to not have a leading 0 */)
			crc8string = "0" + crc8string;
		int crc16int = e16.update(stringbytes);
		crc16string = Integer.toHexString(crc16int).toUpperCase();
		if (crc16int < 0x1000 /* the first number to not have a leading 0 */)
			crc16string = "0" + crc16string;
		e32.update(stringbytes);
		long crc32long = e32.getValue();
		crc32string = Long.toHexString(crc32long).toUpperCase();
		if (crc32long < 0x10000000 /* the first number to not have a leading 0 */)
			crc32string = "0" + crc32string;
		ae32.update(stringbytes);
		long adler32long = ae32.getValue();
		adler32string = Long.toHexString(adler32long).toUpperCase();
		if (adler32long < 0x10000000 /* the first number to not have a leading 0 */)
			adler32string = "0" + adler32string;
		e64.update(stringbytes);
		long crc64long = e64.getValue();
		crc64string = Long.toHexString(crc64long).toUpperCase();
		if (crc64long < 0x1000000000000000L /* the first number to not have a leading 0 */)
			crc64string = "0" + crc64string;
		md2string = DigestUtils.md2Hex(stringbytes).toUpperCase();
		e4.engineUpdate(stringbytes, 0, stringbytes.length);
		byte[] md4hashbytes = e4.engineDigest();
		md4string = Hexdump.toHexString(md4hashbytes, 0, md4hashbytes.length * 2);
		exyz.engineUpdate(stringbytes, 0, stringbytes.length);
		byte[] xyzhashbytes = exyz.engineDigest();
		xyzstring = Hexdump.toHexString(xyzhashbytes, 0, xyzhashbytes.length * 2);
		md5string = DigestUtils.md5Hex(stringbytes).toUpperCase();
		ermd.update(stringbytes);
		byte[] ripemdbytes = ermd.digest();
		ripemdstring = Hexdump.toHexString(ripemdbytes, 0, ripemdbytes.length * 2);
		e128.update(stringbytes);
		byte[] ripemd128bytes = e128.digest();
		ripemd128string = Hexdump.toHexString(ripemd128bytes, 0, ripemd128bytes.length * 2);
		e160.update(stringbytes);
		byte[] ripemd160bytes = e160.digest();
		ripemd160string = Hexdump.toHexString(ripemd160bytes, 0, ripemd160bytes.length * 2);
		e0.update(stringbytes);
		byte[] sha0bytes = e0.digest();
		sha0string = Hexdump.toHexString(sha0bytes, 0, sha0bytes.length * 2);
		sha1string = DigestUtils.sha1Hex(stringbytes).toUpperCase();
		sha224string = DigestUtils.sha224Hex(stringbytes).toUpperCase();
		sha256string = DigestUtils.sha256Hex(stringbytes).toUpperCase();
		sha384string = DigestUtils.sha384Hex(stringbytes).toUpperCase();
		sha512string = DigestUtils.sha512Hex(stringbytes).toUpperCase();
		et.update(stringbytes);
		byte[] tigerbytes = et.digest();
		tigerstring = Hexdump.toHexString(tigerbytes, 0, tigerbytes.length * 2);
		et2.update(stringbytes);
		byte[] tiger2bytes = et2.digest();
		tiger2string = Hexdump.toHexString(tiger2bytes, 0, tiger2bytes.length * 2);
		ew1.update(stringbytes);
		byte[] whirlpool0bytes = ew1.digest();
		whirlpool0string = Hexdump.toHexString(whirlpool0bytes, 0, whirlpool0bytes.length * 2);
		ew2.update(stringbytes);
		byte[] whirlpool1bytes = ew2.digest();
		whirlpool1string = Hexdump.toHexString(whirlpool1bytes, 0, whirlpool1bytes.length * 2);
		ew.update(stringbytes);
		byte[] whirlpoolbytes = ew.digest();
		whirlpoolstring = Hexdump.toHexString(whirlpoolbytes, 0, whirlpoolbytes.length * 2);
	}
}
