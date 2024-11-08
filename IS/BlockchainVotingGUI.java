import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Random;

class Vote {
    private String voterId;
    private String candidate;

    public Vote(String voterId, String candidate) {
        this.voterId = voterId;
        this.candidate = candidate;
    }

    public String getVoterId() {
        return voterId;
    }

    public String getCandidate() {
        return candidate;
    }

    @Override
    public String toString() {
        return "Vote [Voter ID: " + voterId + ", Candidate: " + candidate + "]";
    }
}

class Block {
    public String hash;
    public String previousHash;
    private String data; // Vote data in this case
    private long timeStamp; // When the block is created

    public Block(String data, String previousHash) {
        this.data = data;
        this.previousHash = previousHash;
        this.timeStamp = System.currentTimeMillis();
        this.hash = calculateHash(); // Calculate the hash of this block
    }

    public String getData() {
        return data;      //get data 
    }

    public String calculateHash() {
        String input = previousHash + Long.toString(timeStamp) + data;
        return applySha256(input);
    }

    public static String applySha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes("UTF-8"));
            StringBuilder hexString = new StringBuilder(); // Convert byte array to hex string
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}

class Blockchain {
    private ArrayList<Block> blockchain;
    private HashSet<String> voterRegistry;

    public Blockchain() {
        blockchain = new ArrayList<>();
        voterRegistry = new HashSet<>();
        blockchain.add(new Block("Genesis Block", "0"));
    }

    public String addBlock(Vote vote) {
        if (voterRegistry.contains(vote.getVoterId())) {
            return "Voter has already voted!";
        } else {
            voterRegistry.add(vote.getVoterId());
            String voteData = vote.toString();
            Block previousBlock = blockchain.get(blockchain.size() - 1);
            Block newBlock = new Block(voteData, previousBlock.hash);
            blockchain.add(newBlock);

            // Log the vote to a file
            logVoteToFile(vote);
            return "Vote added! Block Hash: " + newBlock.hash;
        }
    }

    private void logVoteToFile(Vote vote) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter("voting_records.txt", true))) {
            writer.write(vote.toString());
            writer.newLine();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public boolean isChainValid() {
        for (int i = 1; i < blockchain.size(); i++) {
            Block currentBlock = blockchain.get(i);
            Block previousBlock = blockchain.get(i - 1);
            if (!currentBlock.hash.equals(currentBlock.calculateHash())) {
                return false;
            }
            if (!currentBlock.previousHash.equals(previousBlock.hash)) {
                return false;
            }
        }
        return true;
    }

    public String displayBlockchain() {
        StringBuilder blockchainData = new StringBuilder();
        for (Block block : blockchain) {
            blockchainData.append("Block Hash: ").append(block.hash).append("\n");
            blockchainData.append("Previous Hash: ").append(block.previousHash).append("\n");
            blockchainData.append("Data: ").append(block.getData()).append("\n\n");
        }
        return blockchainData.toString();
    }
}

public class BlockchainVotingGUI extends JFrame implements ActionListener {
    private JTextField voterIdField, passwordField, otpField;
    private JComboBox<String> candidateComboBox;
    private JButton voteButton, displayButton, validateButton, requestOtpButton;
    private JTextArea displayArea;
    private Blockchain votingBlockchain;
    private String currentVoterId;
    private HashMap<String, String> voters; // Store voter credentials
    private HashMap<String, String> otpStore; // Store OTPs

    public BlockchainVotingGUI() {
        // Initialize voters and OTP storage
        voters = new HashMap<>();
        otpStore = new HashMap<>();
        
        // Sample voters (Voter ID, Password)
        voters.put("voter1", "password1");
        voters.put("voter2", "password2");
        voters.put("voter3", "password3");

        // Set up the blockchain
        votingBlockchain = new Blockchain();

        // Set up the frame
        setTitle("Blockchain Voting System");
        setSize(600, 400);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setLayout(new BorderLayout());

        // Input panel
        JPanel inputPanel = new JPanel(new GridLayout(5, 2));
        inputPanel.add(new JLabel("Voter ID:"));
        voterIdField = new JTextField();
        inputPanel.add(voterIdField);

        inputPanel.add(new JLabel("Password:"));
        passwordField = new JPasswordField();
        inputPanel.add(passwordField);

        inputPanel.add(new JLabel("Enter OTP:"));
        otpField = new JTextField();
        inputPanel.add(otpField);

        inputPanel.add(new JLabel("Choose Candidate:"));
        candidateComboBox = new JComboBox<>(new String[]{"Candidate A", "Candidate B", "Candidate C"});
        inputPanel.add(candidateComboBox);

        requestOtpButton = new JButton("Request OTP");
        requestOtpButton.addActionListener(this);
        inputPanel.add(requestOtpButton);

        voteButton = new JButton("Vote");
        voteButton.addActionListener(this);
        inputPanel.add(voteButton);

        // Display area for blockchain
        displayArea = new JTextArea();
        displayArea.setEditable(false);

        // Button panel
        JPanel buttonPanel = new JPanel();
        displayButton = new JButton("Display Blockchain");
        displayButton.addActionListener(this);
        buttonPanel.add(displayButton);

        validateButton = new JButton("Validate Blockchain");
        validateButton.addActionListener(this);
        buttonPanel.add(validateButton);

        // Add components to the frame
        add(inputPanel, BorderLayout.NORTH);
        add(new JScrollPane(displayArea), BorderLayout.CENTER);
        add(buttonPanel, BorderLayout.SOUTH);

        setVisible(true);
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        if (e.getSource() == requestOtpButton) {
            String voterId = voterIdField.getText();
            String password = passwordField.getText();
            if (voters.containsKey(voterId) && voters.get(voterId).equals(password)) {
                currentVoterId = voterId;
                String otp = generateOtp();
                otpStore.put(voterId, otp);
                JOptionPane.showMessageDialog(this, "OTP sent: " + otp, "OTP Sent", JOptionPane.INFORMATION_MESSAGE);
            } else {
                JOptionPane.showMessageDialog(this, "Invalid Voter ID or Password", "Error", JOptionPane.ERROR_MESSAGE);
            }
        } else if (e.getSource() == voteButton) {
            String otp = otpField.getText();
            if (otp.equals(otpStore.get(currentVoterId))) {
                String candidate = (String) candidateComboBox.getSelectedItem();
                Vote vote = new Vote(currentVoterId, candidate);
                String result = votingBlockchain.addBlock(vote);
                JOptionPane.showMessageDialog(this, result, "Vote Status", JOptionPane.INFORMATION_MESSAGE);
                voterIdField.setText("");
                passwordField.setText("");
                otpField.setText("");
            } else {
                JOptionPane.showMessageDialog(this, "Invalid OTP", "Error", JOptionPane.ERROR_MESSAGE);
            }
        } else if (e.getSource() == displayButton) {
            String blockchainData = votingBlockchain.displayBlockchain();
            displayArea.setText(blockchainData);
        } else if (e.getSource() == validateButton) {
            if (votingBlockchain.isChainValid()) {
                JOptionPane.showMessageDialog(this, "Blockchain is Valid", "Validation", JOptionPane.INFORMATION_MESSAGE);
            } else {
                JOptionPane.showMessageDialog(this, "Blockchain is NOT Valid", "Validation", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private String generateOtp() {
        Random rand = new Random();
        return String.valueOf(100000 + rand.nextInt(900000)); // Generate a 6-digit OTP
    }

    public static void main(String[] args) {
        new BlockchainVotingGUI();
    }
}