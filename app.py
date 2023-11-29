from flask import Flask, render_template, request
import asyncio
from truecallerpy import search_phonenumber

app = Flask(__name__)

@app.route('/', methods=["POST", "GET"])
def test_truecaller():
    if request.method == "POST":
        # phone_number = "02488811774"
        phone = request.form["phone_number"]
        country_code = "VN"
        installation_id = "a1i0I--jMM3uXFb-ofc-ODmqyAGq8gHtLFxVeOdmifPv9kJWNeNABir5r72aykMM"

        response = asyncio.run(search_phonenumber(phone, country_code, installation_id))
        try:
            name_value = response['data']['data'][0]['name']
            if name_value:
                print(name_value)
        except KeyError:
            # Handling the specific exception
            name_value = "Normal"
        # print(response['data'][0]['name'])
        print(name_value)
        print(response)
        # print(response)
        # Accessing the 'name' value
        # name_value = response['data']['data'][0]['name']
        return render_template('index.html', result=name_value)
    else:    
        return render_template('index.html')

if __name__ == "__main__":
    app.run(debug=True)






