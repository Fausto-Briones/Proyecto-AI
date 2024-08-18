import joblib
from sklearn.ensemble import RandomForestClassifier

class Model:
    def __init__(self):
        self.model = joblib.load('model.joblib')

    def predict(self, input_data):
        return self.model.predict(input_data)