import argparse
import requests
from bs4 import BeautifulSoup
import logging
import re
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="vscan-form-field-analyzer: Identifies and analyzes HTML form fields for potential vulnerabilities.")
    parser.add_argument("url", help="The URL to analyze.")
    parser.add_argument("-o", "--output", help="Output file to save the results (optional).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output for debugging.")
    return parser.parse_args()


def analyze_form_fields(html_content, url):
    """
    Analyzes HTML form fields for potential vulnerabilities.

    Args:
        html_content (str): The HTML content of the page.
        url (str): The URL of the page being analyzed (for context in logs/reports).

    Returns:
        list: A list of dictionaries, where each dictionary represents a form field
              and its potential vulnerabilities.  Returns an empty list if no forms are found.
    """

    soup = BeautifulSoup(html_content, 'html.parser')
    forms = soup.find_all('form')
    results = []

    if not forms:
        logging.warning(f"No forms found on {url}")
        return results

    for form in forms:
        for input_field in form.find_all('input'):
            field_data = {
                'name': input_field.get('name', 'N/A'),
                'type': input_field.get('type', 'text'),  # Default to 'text' if no type is specified
                'autocomplete': input_field.get('autocomplete', 'off'), # Default to 'off' if not specified
                'required': input_field.has_attr('required'),
                'readonly': input_field.has_attr('readonly'),
                'disabled': input_field.has_attr('disabled'),
                'value': input_field.get('value', 'N/A'),
                'placeholder': input_field.get('placeholder', 'N/A'),
                'vulnerabilities': []
            }

            # Check for missing input validation (simple regex for email/number)
            if field_data['type'] == 'email' and field_data['value'] != 'N/A' and not re.match(r"[^@]+@[^@]+\.[^@]+", field_data['value']):
                field_data['vulnerabilities'].append("Potential missing email validation.")
            elif field_data['type'] in ('number', 'tel') and field_data['value'] != 'N/A' and not field_data['value'].isdigit():
                field_data['vulnerabilities'].append("Potential missing numerical validation.")

            # Check for autocomplete enabled on sensitive fields
            if field_data['type'] in ('password', 'credit-card', 'cvv') and field_data['autocomplete'] != 'off':
                field_data['vulnerabilities'].append(f"Autocomplete is enabled for sensitive field of type '{field_data['type']}'.  This is generally discouraged")

            # Check for missing required attribute
            if field_data['type'] not in ('hidden', 'submit', 'button') and not field_data['required']:
               field_data['vulnerabilities'].append("Missing 'required' attribute. Consider adding for important fields")

            if field_data['vulnerabilities']:
                logging.warning(f"Potential vulnerabilities found in field '{field_data['name']}' on {url}")

            results.append(field_data)

    return results


def fetch_html_content(url):
    """
    Fetches the HTML content from the given URL.

    Args:
        url (str): The URL to fetch.

    Returns:
        str: The HTML content, or None on error.
    """
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        return response.text
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching URL {url}: {e}")
        return None



def save_results(results, filename):
    """
    Saves the analysis results to a file.

    Args:
        results (list): The analysis results (list of dictionaries).
        filename (str): The name of the file to save to.
    """
    try:
        with open(filename, 'w') as f:
            import json
            json.dump(results, f, indent=4)  # Save as JSON for readability
        logging.info(f"Results saved to {filename}")
    except IOError as e:
        logging.error(f"Error saving results to {filename}: {e}")


def main():
    """
    Main function to orchestrate the vulnerability scanning process.
    """
    args = setup_argparse()

    # Input validation
    if not args.url.startswith("http://") and not args.url.startswith("https://"):
        print("Error: URL must start with http:// or https://")
        sys.exit(1)

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)  # Enable debug logging

    html_content = fetch_html_content(args.url)

    if html_content:
        results = analyze_form_fields(html_content, args.url)

        if results:
            print("Form field analysis results:")
            for field in results:
                print(f"  Field Name: {field['name']}")
                print(f"    Type: {field['type']}")
                print(f"    Autocomplete: {field['autocomplete']}")
                print(f"    Required: {field['required']}")
                print(f"    Vulnerabilities: {field['vulnerabilities'] or 'None'}")
                print("-" * 20)

            if args.output:
                save_results(results, args.output)
        else:
            print("No vulnerable form fields found.")

    else:
        print("Failed to fetch HTML content. Check the URL and your network connection.")



if __name__ == "__main__":
    main()