#!/usr/bin/env python3
"""
SecurePass Flask Web Application
A beautiful web interface for password security checking
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for
from securepass import PasswordChecker
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Initialize password checker
checker = PasswordChecker()


@app.route('/')
def index():
    """Main page with password checker form"""
    return render_template('index.html')


@app.route('/check', methods=['POST'])
def check_password():
    """API endpoint for password checking"""
    try:
        data = request.get_json()
        password = data.get('password', '').strip()
        
        if not password:
            return jsonify({
                'error': 'Password is required'
            }), 400
        
        # Analyze password
        analysis = checker.analyze_password(password)
        
        # Prepare response
        response = {
            'password_length': len(password),
            'is_breached': analysis['is_breached'],
            'breach_count': analysis['breach_count'],
            'strength_score': analysis['strength_analysis']['score'],
            'strength_level': analysis['strength_analysis']['strength'],
            'strength_color': analysis['strength_analysis']['color'],
            'feedback': analysis['strength_analysis']['feedback'],
            'suggestions': analysis['suggestions'],
            'has_upper': analysis['strength_analysis']['has_upper'],
            'has_lower': analysis['strength_analysis']['has_lower'],
            'has_digit': analysis['strength_analysis']['has_digit'],
            'has_special': analysis['strength_analysis']['has_special']
        }
        
        return jsonify(response)
        
    except Exception as e:
        return jsonify({
            'error': f'An error occurred: {str(e)}'
        }), 500


@app.route('/api/check', methods=['POST'])
def api_check_password():
    """REST API endpoint for external integrations"""
    try:
        data = request.get_json()
        password = data.get('password', '').strip()
        
        if not password:
            return jsonify({
                'error': 'Password is required',
                'status': 'error'
            }), 400
        
        # Analyze password
        analysis = checker.analyze_password(password)
        
        # Prepare API response
        response = {
            'status': 'success',
            'password_length': len(password),
            'breach_check': {
                'is_breached': analysis['is_breached'],
                'breach_count': analysis['breach_count']
            },
            'strength_analysis': {
                'score': analysis['strength_analysis']['score'],
                'level': analysis['strength_analysis']['strength'],
                'feedback': analysis['strength_analysis']['feedback']
            },
            'recommendations': analysis['suggestions'],
            'character_analysis': {
                'has_uppercase': analysis['strength_analysis']['has_upper'],
                'has_lowercase': analysis['strength_analysis']['has_lower'],
                'has_numbers': analysis['strength_analysis']['has_digit'],
                'has_special_chars': analysis['strength_analysis']['has_special']
            }
        }
        
        return jsonify(response)
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': f'An error occurred: {str(e)}'
        }), 500


@app.route('/demo')
def demo():
    """Demo page showing example results"""
    # Example analysis for demo purposes
    demo_password = "Password123"
    analysis = checker.analyze_password(demo_password)
    
    return render_template('demo.html', 
                         analysis=analysis,
                         demo_password=demo_password)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
