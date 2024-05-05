from flask import Flask, render_template, request
import numpy as np

from feature import FeatureExtraction
import pickle
from sklearn import metrics

app = Flask(__name__)

file = open("model.pkl","rb")
mdl = pickle.load(file)
file.close()


@app.route("/", methods=["GET"])
def hello_world_app2():
    return render_template('index.html',xx =-1)

@app.route("/home", methods=["GET", "POST"])
def hello_world_app3():
    if request.method == "POST":
        url = request.form["url"]
        obj = FeatureExtraction(url)
        print(obj.getFeaturesList())
        x = np.array(obj.getFeaturesList()).reshape(1,10)
        y_pred =mdl.predict(x)[0]
        print(url)
        print(y_pred)
        y_pro_non_phishing = mdl.predict_proba(x)[0,0]
        y_pro_phishing = mdl.predict_proba(x)[0,1]

        print(y_pro_phishing)
        print(y_pro_non_phishing)
        pred = "It is {0:.2f} % safe to go ".format(y_pro_non_phishing*100)
        return render_template('index2.html',xx =round(y_pro_non_phishing,2),url=url )
        #return render_template('index2.html',xx = y_pred)
    return render_template('index2.html',xx =-1)


if __name__ == "__main__":
    app.run(port=8081,debug=True)
    
    
    