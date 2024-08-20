import joblib

class Model:
    def __init__(self):
        self.model = joblib.load('gbm_model.joblib')

    def predict(self, input_data):
        return self.model.predict(input_data)