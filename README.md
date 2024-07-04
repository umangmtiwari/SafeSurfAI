# SafeSurfAI

SafeSurfAI is a web application designed to detect phishing websites using a machine learning model. By analyzing various features of a URL, SafeSurfAI can determine whether a website is potentially malicious or safe to use. This project leverages Python, Flask, BeautifulSoup, and a RandomForestClassifier to provide reliable phishing detection.

## Features

- **URL Analysis**: Extracts and analyzes features from the provided URL.
- **Machine Learning Model**: Uses a pre-trained RandomForestClassifier for prediction.
- **Phishing Detection**: Identifies phishing websites with high accuracy.
- **User-Friendly Interface**: Simple and intuitive web interface for easy usage.

## Installation

### Prerequisites

- Python 3.x
- pip (Python package installer)

### Steps

1. **Clone the repository**
    ```bash
    git clone https://github.com/umangmtiwari/SafeSurfAI.git
    cd SafeSurfAI
    ```

2. **Install the required packages**
    ```bash
    pip install -r requirements.txt
    ```

3. **Run the application**
    ```bash
    python app.py
    ```

4. **Open your browser** and navigate to `http://127.0.0.1:5000/` to access SafeSurfAI.

## Usage

1. **Enter URL**: On the home page, enter the URL you want to check.
2. **Analyze**: Click the "Analyze" button to submit the URL.
3. **View Results**: The application will display whether the URL is safe or a phishing site, along with the extracted features.

## Screenshots

### Home Page

![image](https://github.com/umangmtiwari/SafeSurfAI/assets/143312015/1bb1db68-14f2-4696-b9ab-619b9eeb5624)

### Analysis Result

![image](https://github.com/umangmtiwari/SafeSurfAI/assets/143312015/7037d02b-c472-44ac-a064-69103a8d7009)

### Screenshots
![image](https://github.com/umangmtiwari/SafeSurfAI/assets/143312015/71743bff-080c-4ef9-a3bb-a7cb74d91342)

![image](https://github.com/umangmtiwari/SafeSurfAI/assets/143312015/cda78334-10a1-4184-9508-2e4531e53cf8)

![image](https://github.com/umangmtiwari/SafeSurfAI/assets/143312015/70ed8e73-809c-4bb5-82bf-fa9dee25356e)

![image](https://github.com/umangmtiwari/SafeSurfAI/assets/143312015/eb0f6582-4099-4378-b5ba-977a588bc3bb)

## Project Structure

- `mobile.py`: Main application file containing Flask app and URL analysis logic.
- `templates/`: HTML templates for the web interface.
  - `index.html`: Main template for home page and displaying results.
- `static/`: Static files like CSS and JavaScript.
- `phishing.csv`: Dataset used for training the machine learning model.
- `requirements.txt`: List of required Python packages.

## Contributing

Contributions are welcome! Please follow these steps to contribute:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature-branch`).
3. Make your changes.
4. Commit your changes (`git commit -m 'Add some feature'`).
5. Push to the branch (`git push origin feature-branch`).
6. Open a pull request.

This project is licensed under the MIT License.

## Contact

For any questions or feedback, please contact [umangtiwari009@gmail.com](mailto:umangtiwari009@gmail.com).
