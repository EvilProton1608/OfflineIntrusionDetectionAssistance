package model;

public class FileEvent {
    private String filePath;
    private String hash;
    private double entropy;
    private String status;

    public FileEvent(String filePath, String hash, double entropy, String status) {
        this.filePath = filePath;
        this.hash = hash;
        this.entropy = entropy;
        this.status = status;
    }

    // Getters
    public String getFilePath() {
        return filePath;
    }

    public String getHash() {
        return hash;
    }

    public double getEntropy() {
        return entropy;
    }

    public String getStatus() {
        return status;
    }

    // Setters
    public void setFilePath(String filePath) {
        this.filePath = filePath;
    }

    public void setHash(String hash) {
        this.hash = hash;
    }

    public void setEntropy(double entropy) {
        this.entropy = entropy;
    }

    public void setStatus(String status) {
        this.status = status;
    }
}
