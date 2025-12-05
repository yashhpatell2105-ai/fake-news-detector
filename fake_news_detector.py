"""
Fake News Detection Module - Enhanced Version
Implements advanced source credibility verification and fact-checking
"""

import os
import re
import requests
from bs4 import BeautifulSoup
from typing import Dict, Optional, List, Tuple
import warnings
from datetime import datetime, timedelta
from urllib.parse import urlparse, urljoin
import ssl
import socket
warnings.filterwarnings('ignore')

# Try to import optional dependencies
try:
    import tldextract
    TLDEXTRACT_AVAILABLE = True
except ImportError:
    TLDEXTRACT_AVAILABLE = False

try:
    from sentence_transformers import SentenceTransformer
    import numpy as np
    SEMANTIC_AVAILABLE = True
except ImportError:
    SEMANTIC_AVAILABLE = False

try:
    import textstat
    TEXTSTAT_AVAILABLE = True
except ImportError:
    TEXTSTAT_AVAILABLE = False


class FakeNewsDetector:
    """Enhanced fake news detector with advanced source credibility verification"""
    
    def __init__(self):
        """Initialize the detector"""
        self.ai_provider = os.getenv("AI_PROVIDER", "").lower()  # 'gemini' or 'grok' or 'openai-compatible'
        self.ai_api_key = os.getenv("AI_API_KEY")
        self.ai_model = os.getenv("AI_MODEL", "")
        self.ai_endpoint = os.getenv("AI_ENDPOINT", "")  # override for custom endpoints
        self.suspicious_keywords = [
            'breaking', 'shocking', 'doctors hate', 'they don\'t want you to know',
            'secret', 'miracle', 'guaranteed', 'instant', 'one weird trick',
            'share this', 'viral', 'you won\'t believe', 'click here'
        ]
        
        # Comprehensive trusted publisher whitelist
        self.trusted_domains = {
            # Major International News
            'bbc.com', 'bbc.co.uk', 'reuters.com', 'ap.org', 'apnews.com',
            'nytimes.com', 'theguardian.com', 'washingtonpost.com', 'wsj.com',
            'npr.org', 'pbs.org', 'cnn.com', 'abcnews.go.com', 'cbsnews.com',
            'aljazeera.com', 'aljazeera.net', 'dw.com', 'france24.com',
            
            # US Major Newspapers
            'latimes.com', 'chicagotribune.com', 'bostonglobe.com', 'usatoday.com',
            'usnews.com', 'time.com', 'newsweek.com', 'theatlantic.com',
            
            # UK Major Newspapers
            'telegraph.co.uk', 'independent.co.uk', 'standard.co.uk',
            'ft.com', 'economist.com',
            
            # EU Major News
            'lemonde.fr', 'spiegel.de', 'repubblica.it', 'elpais.com',
            
            # India Major News
            'thehindu.com', 'indiatimes.com', 'hindustantimes.com',
            
            # Other Trusted Sources
            'scientificamerican.com', 'nature.com', 'science.org', 'nasa.gov',
            'who.int', 'un.org', 'europa.eu', 'gov.uk', 'gov.au', 'gov.ca'
        }
        
        # Known low-credibility/blacklisted domains
        self.blacklisted_domains = {
            # Add known fake news sites here
            # Example: 'fakenewssite.com'
        }
        
        # Initialize semantic model if available
        self.semantic_model = None
        self.semantic_available = SEMANTIC_AVAILABLE
        if self.semantic_available:
            try:
                self.semantic_model = SentenceTransformer('all-MiniLM-L6-v2')
            except Exception:
                self.semantic_available = False

        # AI assessment availability
        self.ai_available = bool(self.ai_provider and self.ai_api_key)
    
    def normalize_url(self, url: str) -> Tuple[str, str]:
        """Normalize URL and extract domain"""
        if not url:
            return "", ""
        
        # Remove http/https and www
        url = url.lower().strip()
        url = re.sub(r'^https?://', '', url)
        url = re.sub(r'^www\.', '', url)
        
        # Extract domain using tldextract if available
        if TLDEXTRACT_AVAILABLE:
            extracted = tldextract.extract(url)
            domain = f"{extracted.domain}.{extracted.suffix}"
            base_domain = extracted.domain
        else:
            # Fallback to basic parsing
            parsed = urlparse(f"http://{url}")
            domain = parsed.netloc or url.split('/')[0]
            base_domain = domain.split('.')[0] if '.' in domain else domain
        
        # Handle redirects and canonical URLs
        # (In production, you'd follow redirects here)
        canonical_mappings = {
            'bbc.com': 'bbc.co.uk',
            'bbc.co.uk': 'bbc.co.uk',
        }
        
        canonical = canonical_mappings.get(domain, domain)
        return canonical, base_domain
    
    def check_ssl_certificate(self, domain: str) -> Dict[str, any]:
        """Check SSL certificate and organization info"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    org_name = ""
                    if cert and 'subject' in cert:
                        for item in cert['subject']:
                            if item[0][0] == 'organizationName':
                                org_name = item[0][1]
                                break
                    
                    return {
                        'has_ssl': True,
                        'organization': org_name,
                        'score_bonus': 5 if org_name else 0
                    }
        except:
            return {
                'has_ssl': False,
                'organization': None,
                'score_bonus': -15
            }
    
    def estimate_domain_age(self, domain: str) -> Dict[str, any]:
        """Estimate domain age (simplified - in production use WHOIS)"""
        # This is a simplified check - in production, use WHOIS API
        # For now, we'll check if domain looks established
        known_old_domains = {
            'bbc.co.uk', 'reuters.com', 'ap.org', 'nytimes.com',
            'theguardian.com', 'washingtonpost.com'
        }
        
        if domain in known_old_domains:
            return {'age_years': 20, 'score_bonus': 10}
        
        # Check for common patterns that suggest new domains
        suspicious_patterns = ['news', 'info', 'blog', 'site']
        if any(pattern in domain for pattern in suspicious_patterns):
            return {'age_years': 1, 'score_bonus': 0}
        
        # Default assumption
        return {'age_years': 3, 'score_bonus': 0}
    
    def extract_author_metadata(self, text: str, soup: BeautifulSoup = None) -> Dict[str, any]:
        """Extract author information from article"""
        author_name = None
        author_found = False
        
        # Try to find author in HTML metadata
        if soup:
            # Check common meta tags
            author_meta = soup.find('meta', {'name': re.compile('author', re.I)}) or \
                         soup.find('meta', {'property': 'article:author'}) or \
                         soup.find('span', {'class': re.compile('author|byline', re.I)})
            
            if author_meta:
                author_name = author_meta.get('content') or author_meta.get_text()
                author_found = True
        
        # Check text for byline patterns
        if not author_found:
            byline_patterns = [
                r'by\s+([A-Z][a-z]+\s+[A-Z][a-z]+)',
                r'author[:\s]+([A-Z][a-z]+\s+[A-Z][a-z]+)',
                r'written by\s+([A-Z][a-z]+\s+[A-Z][a-z]+)'
            ]
            
            for pattern in byline_patterns:
                match = re.search(pattern, text[:500], re.I)
                if match:
                    author_name = match.group(1)
                    author_found = True
                    break
        
        score_bonus = 0
        if author_found and author_name:
            # Check if author name looks real (has space, proper capitalization)
            if ' ' in author_name and len(author_name.split()) >= 2:
                score_bonus = 8
            else:
                score_bonus = 3
        else:
            score_bonus = -5
        
        return {
            'author': author_name,
            'found': author_found,
            'score_bonus': score_bonus
        }
    
    def check_fact_checking_apis(self, text: str, url: str) -> Dict[str, any]:
        """Check fact-checking APIs (simplified - requires API keys in production)"""
        # Extract key claims from text (simplified)
        sentences = re.split(r'[.!?]+', text)
        key_claims = [s.strip() for s in sentences[:5] if len(s.strip()) > 20]
        
        # In production, integrate with:
        # - Google Fact Check Tools API
        # - PolitiFact API
        # - Snopes API
        # - FactCheck.org API
        
        # For now, return neutral result
        # In production, make API calls here
        fact_check_result = {
            'checked': False,
            'verdict': None,  # 'true', 'false', 'mixed', None
            'source': None,
            'score_bonus': 0
        }
        
        # Simulated check - in production, replace with actual API calls
        # Example structure:
        # if fact_check_api_result:
        #     if fact_check_api_result['verdict'] == 'true':
        #         fact_check_result['score_bonus'] = 20
        #     elif fact_check_api_result['verdict'] == 'false':
        #         fact_check_result['score_bonus'] = -40
        
        return fact_check_result

    def ai_assess_article(self, text: str, source: str, url: str) -> Dict[str, any]:
        """Optional AI (Gemini/Grok/OpenAI-compatible) assessment of article authenticity"""
        if not self.ai_available:
            return {
                'supported': False,
                'verdict': None,
                'score': None,
                'explanation': 'AI provider not configured',
            }

        # Trim text to avoid huge prompts
        prompt_text = text[:4000]
        provider = self.ai_provider

        try:
            if provider == "gemini":
                endpoint = self.ai_endpoint or f"https://generativelanguage.googleapis.com/v1beta/models/{self.ai_model or 'gemini-1.5-flash'}:generateContent?key={self.ai_api_key}"
                payload = {
                    "contents": [
                        {
                            "parts": [
                                {
                                    "text": (
                                        "You are a fact-checking assistant. Rate the likelihood this article is accurate.\n"
                                        "Provide JSON with fields: verdict (true/false/uncertain), score (0-100), "
                                        "explanation (short), and key_signals (list).\n\n"
                                        f"Source: {source}\nURL: {url}\n\nArticle:\n{prompt_text}"
                                    )
                                }
                            ]
                        }
                    ]
                }
                resp = requests.post(endpoint, json=payload, timeout=15)
                resp.raise_for_status()
                data = resp.json()
                text_resp = data.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                return {
                    'supported': True,
                    'verdict': text_resp,
                    'score': None,
                    'explanation': 'Gemini response (parse as needed)'
                }

            # Grok and OpenAI-compatible: use chat completions format
            if provider in ("grok", "openai", "openai-compatible"):
                endpoint = self.ai_endpoint or ("https://api.x.ai/v1/chat/completions" if provider == "grok" else "https://api.openai.com/v1/chat/completions")
                model = self.ai_model or ("grok-beta" if provider == "grok" else "gpt-4o-mini")
                headers = {
                    "Authorization": f"Bearer {self.ai_api_key}",
                    "Content-Type": "application/json",
                }
                messages = [
                    {
                        "role": "system",
                        "content": "You are a fact-checking assistant. Respond with JSON: {verdict: true|false|uncertain, score: 0-100, explanation: short, key_signals: []}"
                    },
                    {
                        "role": "user",
                        "content": f"Source: {source}\nURL: {url}\nArticle:\n{prompt_text}"
                    }
                ]
                payload = {
                    "model": model,
                    "messages": messages,
                    "temperature": 0.2,
                }
                resp = requests.post(endpoint, headers=headers, json=payload, timeout=15)
                resp.raise_for_status()
                data = resp.json()
                content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
                return {
                    'supported': True,
                    'verdict': content,
                    'score': None,
                    'explanation': 'LLM response (parse as needed)'
                }

        except Exception as e:
            return {
                'supported': False,
                'verdict': None,
                'score': None,
                'explanation': f'AI assessment failed: {e}'
            }

        return {
            'supported': False,
            'verdict': None,
            'score': None,
            'explanation': 'Provider not recognized'
        }
    
    def semantic_cross_verification(self, text: str) -> Dict[str, any]:
        """Check semantic similarity with credible news articles"""
        if not self.semantic_available or not self.semantic_model:
            return {
                'verified': False,
                'similarity_score': 0,
                'score_bonus': 0,
                'message': 'Semantic verification not available'
            }
        
        try:
            # Extract key claims (first few sentences)
            sentences = re.split(r'[.!?]+', text)
            key_text = ' '.join(sentences[:3])
            
            # In production, compare against a database of credible articles
            # For now, we'll do a simplified check
            
            # Example credible article snippets (in production, use a vector database)
            credible_snippets = [
                "The World Health Organization announced today that vaccination rates have increased globally",
                "Scientists have published new research findings in peer-reviewed journals",
                "Government officials released an official statement regarding the policy changes"
            ]
            
            if not key_text:
                return {
                    'verified': False,
                    'similarity_score': 0,
                    'score_bonus': 0
                }
            
            # Calculate embeddings
            query_embedding = self.semantic_model.encode([key_text])
            snippet_embeddings = self.semantic_model.encode(credible_snippets)
            
            # Calculate cosine similarity
            similarities = np.dot(query_embedding, snippet_embeddings.T)[0]
            max_similarity = float(np.max(similarities))
            
            score_bonus = 0
            verified = False
            
            if max_similarity >= 0.78:
                verified = True
                if max_similarity >= 0.85:
                    score_bonus = 25  # Multiple confirmations
                else:
                    score_bonus = 15  # Single confirmation
            
            return {
                'verified': verified,
                'similarity_score': round(max_similarity, 3),
                'score_bonus': score_bonus,
                'message': f'Semantic similarity: {max_similarity:.2f}'
            }
        except Exception as e:
            return {
                'verified': False,
                'similarity_score': 0,
                'score_bonus': 0,
                'message': f'Error in semantic verification: {str(e)}'
            }
    
    def check_source_credibility(self, source: str, url: str, text: str = "", soup: BeautifulSoup = None) -> Dict[str, any]:
        """Enhanced source credibility check"""
        score = 50  # Start neutral
        factors = []
        tier = "Unknown"
        is_trusted = False
        is_blacklisted = False
        
        if url:
            normalized_domain, base_domain = self.normalize_url(url)
            
            # Check whitelist
            if normalized_domain in self.trusted_domains:
                is_trusted = True
                score = 80  # Minimum for trusted sources
                tier = "Trusted Publisher"
                factors.append(f"Source '{normalized_domain}' is on the trusted publisher whitelist")
            
            # Check blacklist
            elif normalized_domain in self.blacklisted_domains:
                is_blacklisted = True
                score = 15
                tier = "Low Credibility"
                factors.append(f"Source '{normalized_domain}' is on the blacklist")
            
            else:
                # Unknown source - check reputation
                ssl_info = self.check_ssl_certificate(normalized_domain)
                age_info = self.estimate_domain_age(normalized_domain)
                
                score += ssl_info['score_bonus']
                score += age_info['score_bonus']
                
                if ssl_info['has_ssl']:
                    factors.append("Domain has valid SSL certificate")
                    if ssl_info['organization']:
                        factors.append(f"SSL certificate shows organization: {ssl_info['organization']}")
                else:
                    factors.append("Domain lacks SSL certificate or certificate is invalid")
                
                if age_info['age_years'] >= 5:
                    factors.append(f"Domain appears to be established (estimated {age_info['age_years']}+ years)")
                elif age_info['age_years'] < 0.5:
                    factors.append("Domain appears to be very new (<6 months)")
                
                # Set tier for unknown sources
                if 45 <= score <= 60:
                    tier = "Unknown Source (Neutral)"
                elif score < 45:
                    tier = "Low Credibility"
                else:
                    tier = "Moderate Credibility"
        
        # Author metadata check
        author_info = self.extract_author_metadata(text, soup)
        score += author_info['score_bonus']
        
        if author_info['found']:
            factors.append(f"Article has author byline: {author_info['author']}")
        else:
            factors.append("No author byline found")
        
        # Fact-checking integration
        fact_check = self.check_fact_checking_apis(text, url)
        score += fact_check['score_bonus']
        
        if fact_check['checked']:
            if fact_check['verdict'] == 'true':
                factors.append("Fact-check verification: Claims verified as TRUE")
            elif fact_check['verdict'] == 'false':
                factors.append("Fact-check verification: Claims verified as FALSE")
        
        # Semantic cross-verification
        semantic_check = self.semantic_cross_verification(text)
        score += semantic_check['score_bonus']
        
        if semantic_check['verified']:
            factors.append(f"Semantic cross-verification: Similar claims found in credible sources (similarity: {semantic_check['similarity_score']:.2f})")
        
        # Ensure trusted sources maintain minimum score
        if is_trusted:
            score = max(score, 80)  # Never below 80 for trusted sources
            factors.append("Trusted source protection: Score protected from language/quality penalties")
        
        # Ensure blacklisted sources stay low
        if is_blacklisted:
            score = min(score, 20)
        
        return {
            'score': min(100, max(0, score)),
            'tier': tier,
            'is_trusted': is_trusted,
            'is_blacklisted': is_blacklisted,
            'factors': factors,
            'author_info': author_info,
            'fact_check': fact_check,
            'semantic_check': semantic_check
        }
    
    def analyze_language_patterns(self, text: str, is_trusted: bool = False) -> Dict[str, any]:
        """Analyze language patterns with reduced penalties for trusted sources"""
        score = 50  # Start neutral
        factors = []
        max_penalty = -10 if is_trusted else -50  # Limit penalties for trusted sources
        
        text_lower = text.lower()
        
        # Check for suspicious keywords
        suspicious_count = sum(1 for keyword in self.suspicious_keywords if keyword in text_lower)
        if suspicious_count > 0:
            penalty = min(suspicious_count * 5, abs(max_penalty))
            score -= penalty
            factors.append(f"Found {suspicious_count} suspicious marketing/sensationalist phrases")
        
        # Check for excessive capitalization
        caps_ratio = sum(1 for c in text if c.isupper()) / len(text) if text else 0
        if caps_ratio > 0.3:
            penalty = min(10, abs(max_penalty))
            score -= penalty
            factors.append("Excessive use of capital letters (common in fake news)")
        
        # Check for excessive exclamation marks
        exclamation_count = text.count('!')
        if exclamation_count > len(text) / 100:
            penalty = min(8, abs(max_penalty))
            score -= penalty
            factors.append("Excessive exclamation marks")
        
        # Check readability
        if TEXTSTAT_AVAILABLE:
            try:
                flesch_score = textstat.flesch_reading_ease(text[:1000]) if len(text) > 0 else 50
                if flesch_score < 20 or flesch_score > 90:
                    penalty = min(5, abs(max_penalty))
                    score -= penalty
                    factors.append("Unusual readability score (may indicate manipulation)")
            except:
                pass
        
        # Check for emotional language
        emotional_words = ['amazing', 'incredible', 'unbelievable', 'shocking', 'outrageous']
        emotional_count = sum(1 for word in emotional_words if word in text_lower)
        if emotional_count > 3:
            penalty = min(8, abs(max_penalty))
            score -= penalty
            factors.append("Excessive emotional language")
        
        # Ensure minimum score for trusted sources
        if is_trusted:
            score = max(score, 60)
        
        return {
            'score': min(100, max(0, score)),
            'factors': factors
        }
    
    def check_content_quality(self, text: str, is_trusted: bool = False) -> Dict[str, any]:
        """Check content quality with reduced penalties for trusted sources"""
        score = 50
        factors = []
        max_penalty = -10 if is_trusted else -50  # Limit penalties for trusted sources
        
        if not text or len(text.strip()) < 50:
            return {
                'score': 0,
                'factors': ['Article text is too short or empty']
            }
        
        # Check length
        word_count = len(text.split())
        if word_count < 100:
            penalty = min(20, abs(max_penalty))
            score -= penalty
            factors.append("Article is very short (may lack detail)")
        elif word_count > 2000:
            score += 10
            factors.append("Article has substantial length")
        
        # Check for proper sentence structure
        sentences = re.split(r'[.!?]+', text)
        avg_sentence_length = word_count / len(sentences) if sentences else 0
        
        if avg_sentence_length < 5 or avg_sentence_length > 30:
            penalty = min(10, abs(max_penalty))
            score -= penalty
            factors.append("Unusual sentence structure")
        else:
            score += 5
            factors.append("Normal sentence structure")
        
        # Check for citations or references
        if any(word in text.lower() for word in ['according to', 'study', 'research', 'source', 'cited']):
            score += 15
            factors.append("Article mentions sources or citations")
        
        # Check for quotes
        quote_count = text.count('"') + text.count("'")
        if quote_count > 4:
            score += 10
            factors.append("Article includes quotes (may indicate reporting)")
        
        # Ensure minimum score for trusted sources
        if is_trusted:
            score = max(score, 60)
        
        return {
            'score': min(100, max(0, score)),
            'factors': factors
        }
    
    def extract_text_from_url(self, url: str) -> Tuple[str, BeautifulSoup]:
        """Extract article text from URL and return soup for metadata extraction"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Remove script and style elements
            for script in soup(["script", "style", "nav", "header", "footer", "aside"]):
                script.decompose()
            
            # Try to find main article content
            article = soup.find('article') or soup.find('main') or soup.find('div', class_=re.compile('article|content|post', re.I))
            
            if article:
                text = article.get_text()
            else:
                text = soup.get_text()
            
            # Clean up text
            lines = (line.strip() for line in text.splitlines())
            chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
            text = ' '.join(chunk for chunk in chunks if chunk)
            return text, soup
        except Exception as e:
            return "", None
    
    def analyze_article(self, text: str, source: str = "", url: str = "") -> Dict[str, any]:
        """Enhanced article analysis with improved source credibility"""
        
        soup = None
        if not text and url:
            text, soup = self.extract_text_from_url(url)
        
        if not text:
            return {
                'is_fake': True,
                'confidence': 1.0,
                'score': 0,
                'message': 'No article text provided',
                'source_tier': 'Unknown',
                'details': {}
            }
        
        # Perform source credibility check (enhanced)
        source_analysis = self.check_source_credibility(source, url, text, soup)
        is_trusted = source_analysis.get('is_trusted', False)
        is_blacklisted = source_analysis.get('is_blacklisted', False)
        
        # Perform language and quality analysis with trusted source protection
        language_analysis = self.analyze_language_patterns(text, is_trusted)
        quality_analysis = self.check_content_quality(text, is_trusted)

        # Optional AI assessment (Gemini/Grok/OpenAI-compatible)
        ai_assessment = self.ai_assess_article(text, source, url)
        
        # Apply trusted source protection to scores
        source_score = source_analysis['score']
        language_score = language_analysis['score']
        quality_score = quality_analysis['score']
        
        if is_trusted:
            # Ensure minimum scores for trusted sources
            source_score = max(source_score, 80)
            language_score = max(language_score, 60)
            quality_score = max(quality_score, 60)
        
        # Calculate overall score (weighted average)
        overall_score = (
            source_score * 0.3 +
            language_score * 0.4 +
            quality_score * 0.3
        )
        
        # Ensure trusted sources never drop below 60 unless fact-checked as false
        if is_trusted and not source_analysis['fact_check'].get('verdict') == 'false':
            overall_score = max(overall_score, 60)
        
        # Determine classification
        if is_blacklisted:
            is_fake = True
            confidence = 0.9
            message = "This article is from a known low-credibility source."
        elif overall_score >= 65:
            is_fake = False
            confidence = min(0.95, 0.5 + (overall_score - 65) / 70)
            message = "This article appears to be from a credible source with good quality content."
        elif overall_score >= 50:
            is_fake = False
            confidence = 0.6
            if source_analysis['tier'] == "Unknown Source (Neutral)":
                message = "This article is from an unknown source. Please verify claims with external fact-checking sources."
            else:
                message = "This article shows mixed signals. Exercise caution and verify claims independently."
        elif overall_score >= 35:
            is_fake = False
            confidence = 0.7
            message = "This article has several warning signs. Be skeptical and fact-check claims."
        else:
            is_fake = True
            confidence = min(0.95, 0.5 + (35 - overall_score) / 35)
            message = "This article shows strong indicators of being fake or misleading news."
        
        # Calculate confidence percentage
        confidence_percent = round(confidence * 100, 1)
        
        return {
            'is_fake': is_fake,
            'confidence': confidence,
            'confidence_percent': confidence_percent,
            'score': round(overall_score, 1),
            'source_score': round(source_score, 1),
            'language_score': round(language_score, 1),
            'quality_score': round(quality_score, 1),
            'source_tier': source_analysis['tier'],
            'message': message,
            'ai_assessment': ai_assessment,
            'fact_check_corroboration': source_analysis['fact_check']['checked'],
            'fact_check_verdict': source_analysis['fact_check'].get('verdict'),
            'cross_source_verification': source_analysis['semantic_check']['verified'],
            'cross_source_similarity': source_analysis['semantic_check'].get('similarity_score', 0),
            'explanation': f"Source: {source_analysis['tier']}. Language analysis: {language_score}/100. Content quality: {quality_score}/100.",
            'details': {
                'source_analysis': {
                    'score': source_score,
                    'tier': source_analysis['tier'],
                    'factors': source_analysis['factors'],
                    'author': source_analysis['author_info'].get('author'),
                    'is_trusted': is_trusted,
                    'is_blacklisted': is_blacklisted
                },
                'language_analysis': language_analysis,
                'quality_analysis': quality_analysis,
                'fact_check': source_analysis['fact_check'],
                'semantic_check': source_analysis['semantic_check']
            }
        }
