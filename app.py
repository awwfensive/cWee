from flask import Flask, request, render_template, url_for
import nvdlib
from datetime import datetime, timezone
import math
import time

app = Flask(__name__)

@app.route("/")
def landing():
    return render_template("index.html")  


@app.route("/cwee", methods=["GET"])
def index():
    cves = []
    form_data = {"searchType": [], "searchQuery": []}
    page = int(request.args.get("page", 1))
    per_page = 50
    total_pages = 1
    sort = request.args.get("sort", "asc")
    error_message = None
    total_results = 0

    # handle multi filter form data from query parameters
    search_types = request.args.getlist("searchType[]")
    search_queries = request.args.getlist("searchQuery[]")
    
    print(f"DEBUG - Raw search types: {search_types}")
    print(f"DEBUG - Raw search queries: {search_queries}")
    
    form_data["searchType"] = search_types
    form_data["searchQuery"] = search_queries

    # filter out the empty queries and correctly pair types and queries
    filters = []
    for i in range(len(search_types)):
        if i < len(search_queries) and search_queries[i].strip():
            filters.append({
                "type": search_types[i],
                "query": search_queries[i].strip()
            })
    
    print(f"DEBUG - Active filters: {filters}")

    if filters:
        try:
            # rate limiting to be nice to the NVD API
            time.sleep(0.1)
            
            # Start with first filter - this is our base dataset
            first_filter = filters[0]
            params = {}
            search_type = first_filter["type"]
            search_query = first_filter["query"]
            
            if search_type == "keyword":
                params["keywordSearch"] = search_query
            elif search_type == "cveId":
                params["cveId"] = search_query
            elif search_type == "cpeName":
                params["cpeName"] = search_query
            elif search_type == "severity":
                severity = search_query.upper()
                if severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
                    params["cvssV3Severity"] = severity
                else:
                    error_message = f"Invalid severity '{search_query}'. Use: LOW, MEDIUM, HIGH, or CRITICAL"
            elif search_type == "dateRange":
                try:
                    dates = search_query.split(",")
                    if len(dates) != 2:
                        raise ValueError("Must provide exactly 2 dates separated by comma")
                    
                    start_date = dates[0].strip()
                    end_date = dates[1].strip()
                    
                    # validate date format and convert to datetime objects with timezone
                    start_dt = datetime.strptime(start_date, "%Y-%m-%d")
                    end_dt = datetime.strptime(end_date, "%Y-%m-%d")
                    
                    # Add timezone info and set time to start/end of day
                    start_dt = start_dt.replace(hour=0, minute=0, second=0, tzinfo=timezone.utc)
                    end_dt = end_dt.replace(hour=23, minute=59, second=59, tzinfo=timezone.utc)
                    
                    # nvdlib accepts datetime objects for date parameters
                    params["pubStartDate"] = start_dt
                    params["pubEndDate"] = end_dt
                    
                    print(f"DEBUG - Date range: {start_dt} to {end_dt}")
                except ValueError as e:
                    error_message = f"Invalid date range format. Use YYYY-MM-DD,YYYY-MM-DD. Error: {str(e)}"
                except Exception as e:
                    error_message = f"Error parsing date range: {str(e)}"

            # Only proceed if we have valid params and no errors
            if not error_message and params:
                print(f"Base search with params: {params}")
                
                # get base results from API
                cve_results = nvdlib.searchCVE(**params)
                all_cves = list(cve_results)
                
                print(f"Base filter '{search_type}:{search_query}' found {len(all_cves)} CVEs")
                
                # apply remaining filters as post-processing on the results we have fetched
                for filter_item in filters[1:]:
                    filter_type = filter_item["type"]
                    filter_query = filter_item["query"]
                    
                    print(f"Applying filter '{filter_type}:{filter_query}' to {len(all_cves)} CVEs")
                    
                    filtered_cves = []
                    
                    if filter_type == "keyword":
                        # Search in descriptions
                        keyword_lower = filter_query.lower()
                        for cve in all_cves:
                            for desc in cve.descriptions:
                                if desc.lang == 'en' and keyword_lower in desc.value.lower():
                                    filtered_cves.append(cve)
                                    break
                    
                    elif filter_type == "cveId":
                        # Filter by CVE ID
                        for cve in all_cves:
                            if filter_query.upper() in cve.id.upper():
                                filtered_cves.append(cve)
                    
                    elif filter_type == "severity":
                        # Filter by severity
                        severity_filter = filter_query.upper()
                        for cve in all_cves:
                            if hasattr(cve, 'score') and cve.score and len(cve.score) > 2:
                                if cve.score[2] and cve.score[2].upper() == severity_filter:
                                    filtered_cves.append(cve)
                    
                    elif filter_type == "dateRange":
                        try:
                            dates = filter_query.split(",")
                            start_date = datetime.strptime(dates[0].strip(), "%Y-%m-%d")
                            end_date = datetime.strptime(dates[1].strip(), "%Y-%m-%d")
                            
                            for cve in all_cves:
                                if cve.published:
                                    pub_date = datetime.fromisoformat(cve.published.replace('Z', '+00:00'))
                                    if start_date <= pub_date.replace(tzinfo=None) <= end_date:
                                        filtered_cves.append(cve)
                        except Exception as e:
                            error_message = f"Invalid date range in filter: {filter_query}. Error: {str(e)}"
                            break
                    
                    elif filter_type == "cpeName":
                        # Filter by CPE (check configurations)
                        cpe_lower = filter_query.lower()
                        for cve in all_cves:
                            if hasattr(cve, 'configurations') and cve.configurations:
                                for config in cve.configurations:
                                    if hasattr(config, 'nodes'):
                                        for node in config.nodes:
                                            if hasattr(node, 'cpeMatch'):
                                                for cpe_match in node.cpeMatch:
                                                    if cpe_lower in cpe_match.criteria.lower():
                                                        filtered_cves.append(cve)
                                                        break
                    
                    # Update all_cves with filtered results
                    all_cves = filtered_cves
                    print(f"After applying filter, {len(all_cves)} CVEs remain")

                if all_cves:
                    # Sort CVEs by published date
                    all_cves.sort(
                        key=lambda c: datetime.fromisoformat(c.published.replace('Z', '+00:00')) if c.published else datetime.min,
                        reverse=(sort == "desc")
                    )

                    total_results = len(all_cves)
                    total_pages = math.ceil(total_results / per_page)

                    # Ensure page is within valid range
                    page = max(1, min(page, total_pages))

                    start = (page - 1) * per_page
                    end = start + per_page
                    cves = all_cves[start:end]
                    
                else:
                    error_message = "No CVEs found after applying all filters"
            elif not error_message:
                error_message = "Please provide valid search parameters"

        except Exception as e:
            error_message = f"Error fetching CVEs: {str(e)}"
            print(f"Exception details: {e}")
            import traceback
            traceback.print_exc()

    # create query string for pagination links and sorting links
    query_params = []
    for i in range(len(form_data["searchType"])):
        if i < len(form_data["searchQuery"]) and form_data["searchQuery"][i].strip():
            query_params.append(f"searchType[]={form_data['searchType'][i]}")
            query_params.append(f"searchQuery[]={form_data['searchQuery'][i]}")
    
    query_string = "&".join(query_params)

    return render_template(
        'cwee.html',
        form_data=form_data,
        cves=cves,
        page=page,
        total_pages=total_pages,
        sort=sort,
        error_message=error_message,
        total_results=total_results,
        query_string=query_string,
        request=request,
        any=any, 
        hasattr=hasattr 
    )

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)