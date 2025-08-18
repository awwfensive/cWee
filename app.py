from flask import Flask, request, render_template
import nvdlib as nvd
import math
from datetime import datetime

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    cves = []
    form_data = {"searchType": "keyword", "searchQuery": ""}
    page = int(request.args.get("page", 1))
    per_page = 50
    total_pages = 1
    sort = request.args.get("sort", "desc")  # default set to descending!
    error_message = None

    if request.method == 'POST':
        form_data["searchType"] = request.form.get("searchType", "keyword")
        form_data["searchQuery"] = request.form.get("searchQuery", "").strip()
        page = 1
    else:
        form_data["searchType"] = request.args.get("searchType", "keyword")
        form_data["searchQuery"] = request.args.get("searchQuery", "").strip()
        page = int(request.args.get("page", 1))

    if form_data["searchQuery"]:
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
                error_message = "Invalid date range format. Use YYYY-MM-DD,YYYY-MM-DD"

        try:
            if not error_message:
                all_cves = list(nvd.searchCVE(**params))

                all_cves.sort(
                    key=lambda c: datetime.fromisoformat(c.published[:-1]),
                    reverse=(sort == "desc")
                )

                total_results = len(all_cves)
                total_pages = math.ceil(total_results / per_page)

                start = (page - 1) * per_page
                end = start + per_page
                cves = all_cves[start:end]
        except Exception as e:
            error_message = f"Error fetching CVEs :C"

    return render_template(
        'index.html',
        form_data=form_data,
        cves=cves,
        page=page,
        total_pages=total_pages,
        sort=sort,
        error_message=error_message
    )

if __name__ == '__main__':
    app.run(debug=True)
