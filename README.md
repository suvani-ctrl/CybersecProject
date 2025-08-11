
```markdown
# Malware Detection System for Personal Windows Desktops

## Overview

This project implements an **offline, machine learning-based malware detection system** tailored for personal Windows desktop environments. It leverages a hybrid set of static features extracted from executable files—including Windows API call sequences, byte frequency distributions, and assembly opcode patterns—to accurately classify files as malicious or benign. The system is designed with privacy and usability in mind, operating fully offline to protect sensitive user data while delivering high detection accuracy.

## Features

- **Hybrid Feature Extraction:** Combines API call sequences, byte frequency analysis, and opcodes for comprehensive static malware detection.
- **Random Forest Classifier:** Machine learning model providing a balance between detection accuracy and computational efficiency.
- **Offline Operation:** No cloud connection required, ensuring user privacy and usability in restricted network environments.
- **User-Friendly Interface:** Flask backend with React frontend delivering intuitive workflow and detailed detection reports.
- **High Accuracy:** Achieves approximately 98% malware detection accuracy across diverse malware families.
- **Privacy-Focused:** All processing and data handling occur locally with strict compliance to privacy and security best practices.
- **Modular Design:** Easily extensible for future integration of dynamic analysis or advanced machine learning methods.

## System Architecture

- **Frontend:** React-based user interface for file scanning, visualization of results, and report generation.
- **Backend:** Flask API server handling feature extraction, model inference, and data management.
- **Machine Learning Model:** Random Forest classifier trained on a hybrid feature dataset for robust malware detection.
- **Data Features:** Static analysis includes sequences of Windows API calls, byte frequency histograms, and assembly opcode sequences extracted from executable files.

## Installation

1. Clone the repository:

   ```
   git clone https://github.com/suvani-ctrl/CybersecProject.git

   ```

2. Set up and activate a Python virtual environment:

   ```
   python -m venv venv
   source venv/bin/activate  # On Windows use: venv\Scripts\activate
   ```

3. Install backend dependencies:

   ```
   pip install -r requirements.txt
   ```

4. Install frontend dependencies and start React app:

   ```
   cd frontend
   npm install
   npm start
   ```

5. Run the Flask backend server:

   ```
   cd ..
   flask run
   ```

## Usage

- Use the frontend interface to upload executable files for scanning.
- The system extracts static features and applies the machine learning model to classify files.
- View real-time scan progress and results with clear malware/non-malware notifications.
- Access detailed reports showing feature-based analysis and classification confidence scores.

## Evaluation

- Tested on multiple unseen malware families and benign software, the model showed strong generalization with ~98% accuracy.
- Combining multiple static features reduces false positives and false negatives compared to single-feature approaches.
- Offline operation supports privacy-aware and network-isolated environments.

## Limitations

- Current detection relies on static analysis; dynamic or runtime malware behaviors are not captured.
- The system supports Windows executables only; other platforms are not yet supported.
- Periodic model retraining is required to maintain detection effectiveness against evolving malware.

## Future Work

- Integrate dynamic behavioral analysis to detect malware based on runtime activities.
- Explore deep learning architectures and adversarial training to enhance robustness.
- Implement real-time alerting and endpoint security ecosystem integration.
- Expand platform support to macOS, Linux, and resource-constrained devices.
- Incorporate privacy-preserving federated learning for collaborative model training across devices.

## Contributing

Contributions are welcome! Please submit issues or pull requests with improvements, bug fixes, or new features.


## Contact

For questions or collaboration inquiries, please contact:

- Your Name  
- Email: suvanibasnet8@gmail.com
- GitHub: suvani

---

Thank you for exploring this malware detection project—designed to empower personal Windows users with effective, private, and offline protection against malicious software.
```

<img width="975" height="259" alt="image" src="https://github.com/user-attachments/assets/10090075-9056-43cf-a9aa-84f053f4e8bc" />
<img width="975" height="505" alt="image" src="https://github.com/user-attachments/assets/1d2ea8d1-29c8-4312-b9a5-162365b812a5" />
<img width="975" height="310" alt="image" src="https://github.com/user-attachments/assets/e3ef2ab8-2210-4191-ad39-121a12e9f13c" />

Keylogger
<img width="975" height="618" alt="image" src="https://github.com/user-attachments/assets/fb077fbf-12c5-41eb-b31a-394dbb7ff7e4" />
<img width="975" height="338" alt="image" src="https://github.com/user-attachments/assets/5ee187be-05cb-4b6c-a6f8-bd1b66d22dd9" />
<img width="975" height="323" alt="image" src="https://github.com/user-attachments/assets/1e681d80-41e1-4fa0-97a9-f6d3b66b4320" />

Ransomware
<img width="975" height="366" alt="image" src="https://github.com/user-attachments/assets/382120ca-998d-4f8c-a418-8a5337284d7a" />
<img width="975" height="361" alt="image" src="https://github.com/user-attachments/assets/4decd858-f305-4455-891d-370d01cbb724" />
<img width="975" height="567" alt="image" src="https://github.com/user-attachments/assets/4bebacf1-af3d-471e-ad7d-09574db0ca6f" />
<img width="975" height="240" alt="image" src="https://github.com/user-attachments/assets/98f45461-98ab-4a12-b749-c134bd110bdf" />

Dropper
<img width="975" height="272" alt="image" src="https://github.com/user-attachments/assets/7fe2738c-f2e8-488b-bbd5-22ce45b1d6c9" />
<img width="975" height="518" alt="image" src="https://github.com/user-attachments/assets/7ee53504-7919-49ca-9445-86501888084c" />
<img width="975" height="624" alt="image" src="https://github.com/user-attachments/assets/7b4a77bc-5dd4-4007-ae6e-e201e225e3b2" />
<img width="975" height="343" alt="image" src="https://github.com/user-attachments/assets/0a309e58-dedb-4289-b7d4-a7219bbd48a8" />


Server Side
<img width="975" height="664" alt="image" src="https://github.com/user-attachments/assets/3a7e6484-98e4-471c-829b-c3a1260ab153" />
Logs
<img width="190" height="743" alt="image" src="https://github.com/user-attachments/assets/7d152f3a-bc92-4b73-9965-2b641362341b" />

Yt 
https://youtu.be/NjDL2ca302A















