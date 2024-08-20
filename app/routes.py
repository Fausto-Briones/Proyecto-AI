from flask import request, jsonify, render_template
from . import create_app
from .models import Model
import pandas as pd
from connectionAdapter import ConnectionAdapter
app = create_app()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.json
        model_input = ConnectionAdapter.preprocess_validation_data(data['input'])
        model = Model()
        prediction = model.predict(model_input)
        model = Model()
        prediction = model.predict(model_input)
        return jsonify({'output': prediction})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
@app.route('/data', methods=['GET'])
def get_data():
    data = pd.read_csv('data/database.csv')
    result = data.to_dict(orient='records')
    return jsonify(result)
