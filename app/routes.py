from flask import request, jsonify, render_template
from . import create_app
from .models import Model

app = create_app()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.json
        model_input = data['input']
        model = Model()
        prediction = model.predict(model_input)
        return jsonify({'output': prediction})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
