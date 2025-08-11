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
import java.awt.GraphicsEnvironment;
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
// BigInteger import
import java.math.BigInteger;
// Charset imports
import java.nio.charset.StandardCharsets;
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
import com.amazonaws.util.Base16;
import com.amazonaws.util.Base16Lower;
import org.apache.commons.codec.binary.Base32;
import java.util.Base64;
import com.orwell.util.Ascii85;
import de.bwaldvogel.base91.Base91;
import rawr.util.Base93;
import at.favre.lib.encoding.Base122;
import org.mesh4j.sync.utils.YEnc;
// MD2-SHA512 hash imports
import org.apache.commons.codec.digest.DigestUtils;
import jcifs.util.MD4;
// XYZ hash import (the algorithm of said hash is from https://docstore.mik.ua/orelly/java-ent/security/ch09_03.htm)
import com.xyz.XYZMessageDigest;
// Misc imports
import jcifs.util.Hexdump;
import org.apache.commons.codec.EncoderException;

// define class
public class CRencodingGUI extends JPanel implements ActionListener {
	private static final Logger logger = Logger.getLogger(CRencodingGUI.class.getName());
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
	protected static String base15upperstring;
	protected static String base15lowerstring;
	protected static String base16upperstring;
	protected static String base16lowerstring;
	protected static String base17upperstring;
	protected static String base17lowerstring;
	protected static String base18upperstring;
	protected static String base18lowerstring;
	protected static String base19upperstring;
	protected static String base19lowerstring;
	protected static String base20upperstring;
	protected static String base20lowerstring;
	protected static String base21upperstring;
	protected static String base21lowerstring;
	protected static String base22upperstring;
	protected static String base22lowerstring;
	protected static String base23upperstring;
	protected static String base23lowerstring;
	protected static String base24upperstring;
	protected static String base24lowerstring;
	protected static String base25upperstring;
	protected static String base25lowerstring;
	protected static String base26upperstring;
	protected static String base26lowerstring;
	protected static String base27upperstring;
	protected static String base27lowerstring;
	protected static String base28upperstring;
	protected static String base28lowerstring;
	protected static String base29upperstring;
	protected static String base29lowerstring;
	protected static String base30upperstring;
	protected static String base30lowerstring;
	protected static String base31upperstring;
	protected static String base31lowerstring;
	protected static String base32upperstring;
	protected static String base32lowerstring;
	protected static String base33upperstring;
	protected static String base33lowerstring;
	protected static String base34upperstring;
	protected static String base34lowerstring;
	protected static String base35upperstring;
	protected static String base35lowerstring;
	protected static String base36upperstring;
	protected static String base36lowerstring;
	protected static String base64string;
	protected static String base64ufstring;
	protected static String base64mimestring;
	protected static String base85string;
	protected static String base85nonarrowstring;
	protected static String base91string;
	protected static String base93string;
	protected static String base122string;
	protected static String yencstring;
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
	public static final Base32 b32 = new Base32();
	public static final Base122 b122 = new Base122();
	public static final YEnc eyenc = new YEnc();

	public static void main(String[] args) {
        if (Boolean.getBoolean("java.awt.headless") || GraphicsEnvironment.isHeadless()) {
            logger.severe("Error: This GUI cannot be run in headless mode.");
            System.exit(1);
        }
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
		JFrame frame = new JFrame("Hashing/Encoding GUI");
		frame.setDefaultCloseOperation(3); // JFrame.EXIT_ON_CLOSE
		frame.add(new CRencodingGUI());
		frame.setPreferredSize(new Dimension(1260, 640)); // set the JFrame size so that way you don't have to resize it
															// every time you load the GUI
		frame.setFont(new Font("Arial", Font.PLAIN, 20));
		frame.pack();
		frame.setVisible(true);
	}

	public CRencodingGUI() {
		super(new BorderLayout());
		// setting options for the log
		log.setMargin(new Insets(5, 5, 5, 5));
		log.setEditable(false);
		log.setFont(new Font("Arial", Font.PLAIN, 14));
		JScrollPane logScrollPane = new JScrollPane(log);
		// create buttons and import icons
		openButton = new JButton("Open a File...", createImageIcon("images/Open16.gif"));
		stringButton = new JButton("Hash a String...");
		saveButton = new JButton("Save Hashes/Encoded Strings As...", createImageIcon("images/Save16.gif"));
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
						"Based on the FileChooserDemo2 project (https://docs.oracle.com/javase/tutorial/uiswing/examples/components/index.html#FileChooserDemo2)<br>"
						+
						"Original project part of the Java Swing tutorial on file choosers (https://docs.oracle.com/javase/tutorial/uiswing/components/filechooser.html)<br>"
						+
						"CRC8 Library: JustFLAC (https://github.com/drogatkin/JustFLAC)<br>" +
						"CRC16 Library: Original code by Taha Paksu (http://www.tahapaksu.com/crc) and ported by Ethan Trithon (https://github.com/ethantrithon)<br>"
						+
						"XYZ Library: Original code by Java Enterprise in a Nutshell, 1st Edition (https://docstore.mik.ua/orelly/java-ent/security/ch09_03.htm)<br>"
						+
						"CRC64 Library: Zach Tellman (https://github.com/ztellman/byte-transforms)<br>" +
						"RIPEMD, RIPEMD128, RIPEMD160, SHA-0, Tiger, Tiger2, Whirlpool 2000/2001/2003 Libraries: Burst Project (https://github.com/BurstProject/pocminer)<br>"
						+
						"MD2, MD5, SHA-1/SHA160, SHA224, SHA256, SHA384, and SHA512 Libraries: Apache Commons (https://commons.apache.org)<br>"
						+
						"Base16 Libraries: Amazon AWS SDK (https://github.com/aws/aws-sdk-java)<br>" +
						"Base32 Library: Apache Commons (https://commons.apache.org)<br>" +
						"Base85 Library: Orwell Security Library (https://www.programcreek.com/java-api-examples/index.php?source_dir=orwell-master/Orwell)<br>(Newer library at https://github.com/fzakaria/ascii85)<br>"
						+
						"basE91 Library: rawr51919 (Modified from Benedikt Waldvogel's version @ https://github.com/bwaldvogel/base91)<br>"
						+
						"Original basE91 Library: Joachim Henke (http://base91.sourceforge.net)<br>" +
						"Base93 Library: rawr51919 (Modified from Benedikt Waldvogel's basE91 library which was modified from Joachim Henke's basE91 library)</html>");

		JPanel creditspanel = new JPanel();
		creditspanel.setBackground(Color.white);
		creditspanel.add(creditslabel);

		creditsframe.add(creditspanel);
		creditsframe.setSize(800, 260);
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
		log.append("Base15 (Uppercase): " + base15upperstring + "\n");
		log.append("Base15 (Lowercase): " + base15lowerstring + "\n");
		log.append("Base16 (Uppercase): " + base16upperstring + "\n");
		log.append("Base16 (Lowercase): " + base16lowerstring + "\n");
		log.append("Base17 (Uppercase): " + base17upperstring + "\n");
		log.append("Base17 (Lowercase): " + base17lowerstring + "\n");
		log.append("Base18 (Uppercase): " + base18upperstring + "\n");
		log.append("Base18 (Lowercase): " + base18lowerstring + "\n");
		log.append("Base19 (Uppercase): " + base19upperstring + "\n");
		log.append("Base19 (Lowercase): " + base19lowerstring + "\n");
		log.append("Base20 (Uppercase): " + base20upperstring + "\n");
		log.append("Base20 (Lowercase): " + base20lowerstring + "\n");
		log.append("Base21 (Uppercase): " + base21upperstring + "\n");
		log.append("Base21 (Lowercase): " + base21lowerstring + "\n");
		log.append("Base22 (Uppercase): " + base22upperstring + "\n");
		log.append("Base22 (Lowercase): " + base22lowerstring + "\n");
		log.append("Base23 (Uppercase): " + base23upperstring + "\n");
		log.append("Base23 (Lowercase): " + base23lowerstring + "\n");
		log.append("Base24 (Uppercase): " + base24upperstring + "\n");
		log.append("Base24 (Lowercase): " + base24lowerstring + "\n");
		log.append("Base25 (Uppercase): " + base25upperstring + "\n");
		log.append("Base25 (Lowercase): " + base25lowerstring + "\n");
		log.append("Base26 (Uppercase): " + base26upperstring + "\n");
		log.append("Base26 (Lowercase): " + base26lowerstring + "\n");
		log.append("Base27 (Uppercase): " + base27upperstring + "\n");
		log.append("Base27 (Lowercase): " + base27lowerstring + "\n");
		log.append("Base28 (Uppercase): " + base28upperstring + "\n");
		log.append("Base28 (Lowercase): " + base28lowerstring + "\n");
		log.append("Base29 (Uppercase): " + base29upperstring + "\n");
		log.append("Base29 (Lowercase): " + base29lowerstring + "\n");
		log.append("Base30 (Uppercase): " + base30upperstring + "\n");
		log.append("Base30 (Lowercase): " + base30lowerstring + "\n");
		log.append("Base31 (Uppercase): " + base31upperstring + "\n");
		log.append("Base31 (Lowercase): " + base31lowerstring + "\n");
		log.append("Base32 (Uppercase): " + base32upperstring + "\n");
		log.append("Base32 (Lowercase): " + base32lowerstring + "\n");
		log.append("Base33 (Uppercase): " + base33upperstring + "\n");
		log.append("Base33 (Lowercase): " + base33lowerstring + "\n");
		log.append("Base34 (Uppercase): " + base34upperstring + "\n");
		log.append("Base34 (Lowercase): " + base34lowerstring + "\n");
		log.append("Base35 (Uppercase): " + base35upperstring + "\n");
		log.append("Base35 (Lowercase): " + base35lowerstring + "\n");
		log.append("Base36 (Uppercase): " + base36upperstring + "\n");
		log.append("Base36 (Lowercase): " + base36lowerstring + "\n");
		log.append("Base64: " + base64string + "\n");
		log.append("Base64 (URL/filename safe): " + base64ufstring + "\n");
		log.append("Base64 (MIME): " + base64mimestring + "\n");
		log.append("Base85 (With Arrows): " + base85string + "\n");
		log.append("Base85 (Without Arrows): " + base85nonarrowstring + "\n");
		log.append("basE91: " + base91string + "\n");
		log.append("Base93: " + base93string + "\n");
		log.append("Base122: " + base122string + "\n");
		log.append("yEnc: " + yencstring + "\n");
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

	private static byte[] readFileBytes(FileInputStream filestream) throws IOException {
		String javaVersion = System.getProperty("java.version");
		if (javaVersion.startsWith("1.") || javaVersion.compareTo("9") < 0) {
			// Java 8 or below: use manual read loop
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			// 8 MB buffer used
			byte[] buffer = new byte[8192];
			int bytesRead;
			while ((bytesRead = filestream.read(buffer)) != -1) {
				baos.write(buffer, 0, bytesRead);
			}
			return baos.toByteArray();
		} else {
			// Java 9 or above: use readAllBytes()
			return filestream.readAllBytes();
		}
	}

	private static void getHashes(FileInputStream filestream) {
		try {
			byte[] filebytes = readFileBytes(filestream);
			// generate the hashes/encoded strings and output them to their respective
			// strings, doing whatever operations are needed to make them display correctly
			int crc8int = CRC8.calc(filebytes, filebytes.length) & 0xff;
			crc8string = String.format("%02X", crc8int);
			int crc16int = e16.update(filebytes);
			crc16string = String.format("%04X", crc16int);
			e32.update(filebytes);
			long crc32long = e32.getValue();
			crc32string = String.format("%08X", crc32long);
			ae32.update(filebytes);
			long adler32long = ae32.getValue();
			adler32string = String.format("%08X", adler32long);
			e64.update(filebytes);
			long crc64long = e64.getValue();
			crc64string = String.format("%016X", crc64long);
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
			base15upperstring = new BigInteger(1, filebytes).toString(15).toUpperCase();
			base15lowerstring = new BigInteger(1, filebytes).toString(15);
			byte[] base16upper = Base16.encode(filebytes);
			base16upperstring = new String(base16upper);
			byte[] base16lower = Base16Lower.encode(filebytes);
			base16lowerstring = new String(base16lower);
			base17upperstring = new BigInteger(1, filebytes).toString(17).toUpperCase();
			base17lowerstring = new BigInteger(1, filebytes).toString(17);
			base18upperstring = new BigInteger(1, filebytes).toString(18).toUpperCase();
			base18lowerstring = new BigInteger(1, filebytes).toString(18);
			base19upperstring = new BigInteger(1, filebytes).toString(19).toUpperCase();
			base19lowerstring = new BigInteger(1, filebytes).toString(19);
			base20upperstring = new BigInteger(1, filebytes).toString(20).toUpperCase();
			base20lowerstring = new BigInteger(1, filebytes).toString(20);
			base21upperstring = new BigInteger(1, filebytes).toString(21).toUpperCase();
			base21lowerstring = new BigInteger(1, filebytes).toString(21);
			base22upperstring = new BigInteger(1, filebytes).toString(22).toUpperCase();
			base22lowerstring = new BigInteger(1, filebytes).toString(22);
			base23upperstring = new BigInteger(1, filebytes).toString(23).toUpperCase();
			base23lowerstring = new BigInteger(1, filebytes).toString(23);
			base24upperstring = new BigInteger(1, filebytes).toString(24).toUpperCase();
			base24lowerstring = new BigInteger(1, filebytes).toString(24);
			base25upperstring = new BigInteger(1, filebytes).toString(25).toUpperCase();
			base25lowerstring = new BigInteger(1, filebytes).toString(25);
			base26upperstring = new BigInteger(1, filebytes).toString(26).toUpperCase();
			base26lowerstring = new BigInteger(1, filebytes).toString(26);
			base27upperstring = new BigInteger(1, filebytes).toString(27).toUpperCase();
			base27lowerstring = new BigInteger(1, filebytes).toString(27);
			base28upperstring = new BigInteger(1, filebytes).toString(28).toUpperCase();
			base28lowerstring = new BigInteger(1, filebytes).toString(28);
			base29upperstring = new BigInteger(1, filebytes).toString(29).toUpperCase();
			base29lowerstring = new BigInteger(1, filebytes).toString(29);
			base30upperstring = new BigInteger(1, filebytes).toString(30).toUpperCase();
			base30lowerstring = new BigInteger(1, filebytes).toString(30);
			base31upperstring = new BigInteger(1, filebytes).toString(31).toUpperCase();
			base31lowerstring = new BigInteger(1, filebytes).toString(31);
			byte[] base32 = b32.encode(filebytes);
			base32upperstring = new String(base32);
			base32lowerstring = new String(base32).toLowerCase();
			base33upperstring = new BigInteger(1, filebytes).toString(33).toUpperCase();
			base33lowerstring = new BigInteger(1, filebytes).toString(33);
			base34upperstring = new BigInteger(1, filebytes).toString(34).toUpperCase();
			base34lowerstring = new BigInteger(1, filebytes).toString(34);
			base35upperstring = new BigInteger(1, filebytes).toString(35).toUpperCase();
			base35lowerstring = new BigInteger(1, filebytes).toString(35);
			base36upperstring = new BigInteger(1, filebytes).toString(36).toUpperCase();
			base36lowerstring = new BigInteger(1, filebytes).toString(36);
			byte[] base64 = Base64.getEncoder().encode(filebytes);
			base64string = new String(base64);
			byte[] base64uf = Base64.getUrlEncoder().encode(filebytes);
			base64ufstring = new String(base64uf);
			byte[] base64mime = Base64.getMimeEncoder().encode(filebytes);
			// Base64 MIME normally newlines the hash every 76 characters as per RFC 2045,
			// remove these so it shows up properly in our GUI window
			base64mimestring = new String(base64mime).replaceAll("\\R", "");
			byte[] base85 = Ascii85.encode(filebytes);
			byte[] base85witharrows = Ascii85.addIdentifiers(base85);
			base85string = new String(base85witharrows);
			base85nonarrowstring = new String(base85);
			byte[] base91 = Base91.encode(filebytes);
			base91string = new String(base91);
			byte[] base93 = Base93.encode(filebytes);
			base93string = new String(base93);
			String base122 = b122.encode(filebytes);
			base122string = base122;
			tryEncodeYenc(filebytes);
			// if the file suddenly doesn't exist, or if an I/O error occurred
		} catch (IOException e) {
			log.append("Error when creating file input.\n"); // send this error to the log
		}
	}

	public static void tryEncodeYenc(byte[] filebytes) {
		try {
			byte[] yenc = eyenc.encode(filebytes);
			yencstring = new String(yenc, StandardCharsets.UTF_8);
		} catch (EncoderException e) {
			e.printStackTrace();
		}
	}

	public static void getStringHashes(String string) {
		byte[] stringbytes = string.getBytes();
		int crc8int = CRC8.calc(stringbytes, stringbytes.length) & 0xff;
		crc8string = String.format("%02X", crc8int);
		int crc16int = e16.update(stringbytes);
		crc16string = String.format("%04X", crc16int);
		e32.update(stringbytes);
		long crc32long = e32.getValue();
		crc32string = String.format("%08X", crc32long);
		ae32.update(stringbytes);
		long adler32long = ae32.getValue();
		adler32string = String.format("%08X", adler32long);
		e64.update(stringbytes);
		long crc64long = e64.getValue();
		crc64string = String.format("%016X", crc64long);
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
		base15upperstring = new BigInteger(1, stringbytes).toString(15).toUpperCase();
		base15lowerstring = new BigInteger(1, stringbytes).toString(15);
		byte[] base16upper = Base16.encode(stringbytes);
		base16upperstring = new String(base16upper);
		byte[] base16lower = Base16Lower.encode(stringbytes);
		base16lowerstring = new String(base16lower);
		base17upperstring = new BigInteger(1, stringbytes).toString(17).toUpperCase();
		base17lowerstring = new BigInteger(1, stringbytes).toString(17);
		base18upperstring = new BigInteger(1, stringbytes).toString(18).toUpperCase();
		base18lowerstring = new BigInteger(1, stringbytes).toString(18);
		base19upperstring = new BigInteger(1, stringbytes).toString(19).toUpperCase();
		base19lowerstring = new BigInteger(1, stringbytes).toString(19);
		base20upperstring = new BigInteger(1, stringbytes).toString(20).toUpperCase();
		base20lowerstring = new BigInteger(1, stringbytes).toString(20);
		base21upperstring = new BigInteger(1, stringbytes).toString(21).toUpperCase();
		base21lowerstring = new BigInteger(1, stringbytes).toString(21);
		base22upperstring = new BigInteger(1, stringbytes).toString(22).toUpperCase();
		base22lowerstring = new BigInteger(1, stringbytes).toString(22);
		base23upperstring = new BigInteger(1, stringbytes).toString(23).toUpperCase();
		base23lowerstring = new BigInteger(1, stringbytes).toString(23);
		base24upperstring = new BigInteger(1, stringbytes).toString(24).toUpperCase();
		base24lowerstring = new BigInteger(1, stringbytes).toString(24);
		base25upperstring = new BigInteger(1, stringbytes).toString(25).toUpperCase();
		base25lowerstring = new BigInteger(1, stringbytes).toString(25);
		base26upperstring = new BigInteger(1, stringbytes).toString(26).toUpperCase();
		base26lowerstring = new BigInteger(1, stringbytes).toString(26);
		base27upperstring = new BigInteger(1, stringbytes).toString(27).toUpperCase();
		base27lowerstring = new BigInteger(1, stringbytes).toString(27);
		base28upperstring = new BigInteger(1, stringbytes).toString(28).toUpperCase();
		base28lowerstring = new BigInteger(1, stringbytes).toString(28);
		base29upperstring = new BigInteger(1, stringbytes).toString(29).toUpperCase();
		base29lowerstring = new BigInteger(1, stringbytes).toString(29);
		base30upperstring = new BigInteger(1, stringbytes).toString(30).toUpperCase();
		base30lowerstring = new BigInteger(1, stringbytes).toString(30);
		base31upperstring = new BigInteger(1, stringbytes).toString(31).toUpperCase();
		base31lowerstring = new BigInteger(1, stringbytes).toString(31);
		byte[] base32 = b32.encode(stringbytes);
		base32upperstring = new String(base32);
		base32lowerstring = new String(base32).toLowerCase();
		base33upperstring = new BigInteger(1, stringbytes).toString(33).toUpperCase();
		base33lowerstring = new BigInteger(1, stringbytes).toString(33);
		base34upperstring = new BigInteger(1, stringbytes).toString(34).toUpperCase();
		base34lowerstring = new BigInteger(1, stringbytes).toString(34);
		base35upperstring = new BigInteger(1, stringbytes).toString(35).toUpperCase();
		base35lowerstring = new BigInteger(1, stringbytes).toString(35);
		base36upperstring = new BigInteger(1, stringbytes).toString(36).toUpperCase();
		base36lowerstring = new BigInteger(1, stringbytes).toString(36);
		byte[] base64 = Base64.getEncoder().encode(stringbytes);
		base64string = new String(base64);
		byte[] base64uf = Base64.getUrlEncoder().encode(stringbytes);
		base64ufstring = new String(base64uf);
		byte[] base64mime = Base64.getMimeEncoder().encode(stringbytes);
		// Base64 MIME normally newlines the hash every 76 characters as per RFC 2045,
		// remove these so it shows up properly in our GUI window
		base64mimestring = new String(base64mime).replaceAll("\\R", "");
		byte[] base85 = Ascii85.encode(stringbytes);
		byte[] base85witharrows = Ascii85.addIdentifiers(base85);
		base85string = new String(base85witharrows);
		base85nonarrowstring = new String(base85);
		byte[] base91 = Base91.encode(stringbytes);
		base91string = new String(base91);
		byte[] base93 = Base93.encode(stringbytes);
		base93string = new String(base93);
		String base122 = b122.encode(stringbytes);
		base122string = base122;
		try {
			byte[] yenc = eyenc.encode(stringbytes);
			yencstring = new String(yenc);
		} catch (EncoderException e) {
			e.printStackTrace();
		}
	}
}
