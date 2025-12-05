"""
Fake News Detection System - Main Application
Theme: TRUTH
"""

from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import os
from fake_news_detector import FakeNewsDetector

app = Flask(__name__)
CORS(app)

# Initialize the detector
detector = FakeNewsDetector()

@app.route('/')
def index():
    """Main page"""
    return render_template('index.html')

@app.route('/api/verify', methods=['POST'])
def verify_news():
    """API endpoint for news verification"""
    try:
        data = request.json
        article_text = data.get('text', '')
        article_url = data.get('url', '')
        source = data.get('source', '')
        
        if not article_text and not article_url:
            return jsonify({'error': 'Please provide either article text or URL'}), 400
        
        # If URL provided, try to extract text
        if article_url and not article_text:
            article_text = detector.extract_text_from_url(article_url)
        
        # Perform analysis
        result = detector.analyze_article(
            text=article_text,
            source=source,
            url=article_url
        )
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/demo', methods=['GET'])
def demo_articles():
    """Get demo articles for testing"""
    demo_articles = [
        {
            'title': 'Sample Real News',
            'text': 'The World Health Organization announced today that vaccination rates have increased globally, with over 70% of the world population having received at least one dose of a COVID-19 vaccine. This milestone represents significant progress in global health initiatives.',
            'source': 'WHO Official Press Release',
            'url': 'https://example.com/real-news'
        },
        {
            'title': 'Sample Suspicious News',
            'text': 'BREAKING: Scientists discover that drinking bleach cures all diseases! Doctors are hiding this secret from you! Share this immediately before they delete it!',
            'source': 'Unknown Blog',
            'url': 'https://example.com/fake-news'
        }
    ]
    return jsonify(demo_articles)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)

