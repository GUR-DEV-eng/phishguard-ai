# PhishGuard AI

AI-powered tool to detect and prevent phishing websites using machine learning models trained on phishing URLs.

## Features

- **Machine Learning Detection**: Uses trained ML models to identify phishing websites
- **URL Analysis**: Analyzes URLs for phishing indicators
- **Real-time Protection**: Quick and efficient phishing detection
- **Extensible Architecture**: Easy to integrate and extend with new models

## Prerequisites

- Python 3.8+
- pip (Python package manager)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/phishguard-ai.git
cd phishguard-ai
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up credentials:
```bash
cp credentials.yaml.example credentials.yaml
# Edit credentials.yaml with your configuration
```

## Usage

### Running the Application
```bash
python app.py
```

### Training Models
```bash
python model_training.py
```

## Project Structure

```
phishguard-ai/
├── app.py                 # Main application
├── model_training.py      # Model training script
├── requirements.txt       # Python dependencies
├── credentials.yaml       # Configuration file (not tracked)
├── credentials.yaml.example  # Example credentials template
└── data/
    └── phishing_site_urls.csv  # Training dataset
```

## Data

The `data/` directory contains training datasets used for building and improving the phishing detection models.

## Configuration

Configure the application by editing `credentials.yaml`. Use `credentials.yaml.example` as a template for required settings.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For issues and questions, please open an issue on GitHub.

---

**Note**: This tool is designed for educational and protective purposes. Always ensure you have proper authorization before testing on any website.
