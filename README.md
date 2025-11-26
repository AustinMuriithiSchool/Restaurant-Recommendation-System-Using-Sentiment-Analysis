
# Restaurant Recommendation System Using Sentiment Analysis

NourishNet is a web-based platform that recommends restaurants by analyzing user reviews using advanced sentiment analysis and aspect-based classification. It leverages machine learning (DistilRoBERTa), natural language processing, and integrates with external APIs to provide personalized recommendations and analytics for users and administrators.

## Features
- **Restaurant Search & Recommendation:** Find restaurants based on location and preferences.
- **Sentiment Analysis:** Classifies reviews as positive, negative, or neutral using a fine-tuned DistilRoBERTa model.
- **Aspect-Based Analysis:** Identifies key aspects (food, service, speed, etc.) mentioned in reviews.
- **User Authentication:** Supports registration, login, and Google Sign-In via Firebase.
- **Admin Dashboard:** View analytics and manage reviews.
- **PDF Report Generation:** Export analytics and review summaries.

## Tech Stack
- **Backend:** Flask, MySQL, Firebase Admin SDK
- **Frontend:** HTML, CSS, JavaScript (with templates)
- **ML/NLP:** Transformers, PyTorch, scikit-learn, spaCy
- **External APIs:** Apify for restaurant data

## Setup Instructions

### 1. Clone the Repository
```powershell
git clone https://github.com/AustinMuriithiSchool/Restaurant-Recommendation-System-Using-Sentiment-Analysis.git
cd Restaurant-Recommendation-System-Using-Sentiment-Analysis
```

### 2. Install Python Dependencies
Ensure you have Python 3.8+ installed. Then run:
```powershell
pip install -r restaurant-recommender/requirements.txt
```

### 3. Environment Variables
Create a `.env` file in `restaurant-recommender/` with the following (example):
```
MYSQL_HOST=localhost
MYSQL_USER=root
MYSQL_PASSWORD=yourpassword
MYSQL_DB=nourishnet
FLASK_SECRET=your_flask_secret
SESSION_COOKIE_NAME=__session
SESSION_COOKIE_SECURE=False
APIFY_ACTOR_TASK_ID=your_apify_actor_id
APIFY_API_TOKEN=your_apify_api_token
```

### 4. Database Setup

Create a MySQL database named `nourishnet` and the required tables. Example table for reviews:

```sql
CREATE TABLE restaurant_reviews (
	id INT AUTO_INCREMENT PRIMARY KEY,
	author_name VARCHAR(255),
	place_address VARCHAR(255),
	place_name VARCHAR(255),
	review_url VARCHAR(255) UNIQUE,
	review_title VARCHAR(255),
	review_text TEXT,
	review_rating FLOAT,
	location VARCHAR(100),
	predicted_sentiment VARCHAR(50),
	predicted_aspects TEXT
);
```

Example table for users:

```sql
CREATE TABLE users (
	id INT AUTO_INCREMENT PRIMARY KEY,
	firebase_uid VARCHAR(128) NOT NULL,
	username VARCHAR(100) NOT NULL,
	email VARCHAR(255) NOT NULL,
	role ENUM('admin', 'user') NOT NULL,
	status VARCHAR(20) DEFAULT 'active',
	INDEX (firebase_uid),
	INDEX (email)
);
```

### 5. Firebase Setup
- Create a Firebase project and download the service account JSON.
- Place it as `firebase_service_account.json` in `restaurant-recommender/`.

### 6. Model Files
- The ML models and tokenizers should be placed in `restaurant-recommender/mlmodel/outputs_distilroberta_base_restaurant/` as per the directory structure.
- If not present, retrain using `train_distilroberta.py` or request the files.

### 7. Run the Application
```powershell
python restaurant-recommender/app.py
```
The app will be available at `http://localhost:5000`.

## Usage
- Register or login as a user/admin.
- Search for restaurants and view recommendations.
- Admins can view analytics and export reports.


## License
This project is for educational purposes.
