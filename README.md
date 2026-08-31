# Phishing Detection on Websites

A comprehensive phishing detection system that includes a machine learning model, a Flask API, and a browser extension for real-time detection.

## Features

- **Machine Learning Model**: Trained on phishing dataset to classify websites
- **Flask API**: RESTful API for phishing prediction
- **Browser Extension**: Chrome extension that detects phishing sites in real-timing

## Project Structure

```
├── app.py                 # Flask API application
├── train_model.py         # Script to train the ML model
├── requirements.txt       # Python dependencies
├── README.md              # This file
├── dataset/               # Dataset files
│   └── phishing_dataset.csv
├── model/                 # Trained model files
│   └── phishing_model.pkl
├── extension/             # Browser extension files
│   ├── manifest.json
│   ├── popup.html
│   ├── popup.js
│   ├── content.js
│   └── style.css
├── ml_model/              # Jupyter notebook for model development
│   └── phishing_detection.ipynb
└── anaconda_projects/     # Additional project files
```

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/phishing-detection.git
   cd phishing-detection
   ```

2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Running the Flask API

This project now uses Waitress for production-style serving.

```bash
python app.py
```

Or, if you want to run the WSGI entrypoint directly:

```bash
waitress-serve --listen=0.0.0.0:5000 wsgi:app
```

The API will be available at `http://localhost:5000`

### API Endpoints

- `GET /`: Home page
- `POST /predict`: Predict if a website is phishing
  - Body: `{"features": [list of features]}`
  - Response: `{"prediction": "Legitimate Website" or "Phishing Website"}`

### Browser Extension

1. Open Chrome and go to `chrome://extensions/`
2. Enable "Developer mode"
3. Click "Load unpacked" and select the `extension/` folder
4. The extension will appear in your browser toolbar

## Training the Model

To retrain the model:

```bash
python train_model.py
```

## Deployment

### Deploy to Heroku from GitHub

#### Prerequisites
- Heroku account (create at https://www.heroku.com)
- GitHub repository with this code pushed

#### Setup Steps

1. **Create a new Heroku app:**
   ```bash
   heroku create your-app-name
   ```

2. **Add GitHub secrets to your repository:**
   - Go to your GitHub repository → Settings → Secrets and variables → Actions
   - Add the following secrets:
     - `HEROKU_API_KEY`: Get from https://dashboard.heroku.com/account/applications/authorizations
     - `HEROKU_APP_NAME`: Your Heroku app name (e.g., `your-app-name`)
     - `HEROKU_EMAIL`: Your Heroku account email

3. **Push to main/master branch:**
   ```bash
   git push origin main
   ```
   The GitHub Actions workflow will automatically deploy your app to Heroku!

4. **View your deployed API:**
   ```bash
   heroku open
   ```

#### Manual Heroku Deployment (Alternative)

If you prefer to deploy manually without GitHub Actions:

```bash
# Login to Heroku
heroku login

# Add Heroku remote to your repository
heroku git:remote -a your-app-name

# Deploy
git push heroku main
```

#### API Usage After Deployment

Once deployed, your API will be available at:
```
https://your-app-name.herokuapp.com/predict
```

Example request:
```bash
curl -X POST https://your-app-name.herokuapp.com/predict \
  -H "Content-Type: application/json" \
  -d '{"features": [0.5, 0.3, 0.8, ...]}'
```

## Dataset

The dataset used is `phishing_dataset.csv` which contains various features extracted from URLs for phishing detection.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for educational purposes only. Always exercise caution when visiting websites and use additional security measures.