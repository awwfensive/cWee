from flask import Flask, request, render_template
import nvdlib as nvd

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    cves = []
    form_data = {
        "searchType": "keyword",
        "searchQuery": ""
    }

    if request.method == 'POST':
        form_data["searchType"] = request.form.get("searchType", "keyword")
        form_data["searchQuery"] = request.form.get("searchQuery", "").strip()

        params = {}
        if form_data["searchType"] == "keyword":
            params["keywordSearch"] = form_data["searchQuery"]
        elif form_data["searchType"] == "cveId":
            params["cveId"] = form_data["searchQuery"]
        elif form_data["searchType"] == "cpeName":
            params["cpeName"] = form_data["searchQuery"]
        elif form_data["searchType"] == "severity":
            params["cvssV3Severity"] = form_data["searchQuery"].upper()
        elif form_data["searchType"] == "dateRange":
            try:
                start, end = form_data["searchQuery"].split(",")
                params["pubStartDate"] = start
                params["pubEndDate"] = end
            except ValueError:
                pass

        try:
            cves = nvd.searchCVE(**params)
        except Exception as e:
            return f"Error fetching CVEs: {e}", 500

    return render_template('index.html', form_data=form_data, cves=cves)



if __name__ == '__main__':
    app.run(debug=True)
