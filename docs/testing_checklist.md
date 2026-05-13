# Testing Checklist

Use this checklist before final submission.

## Environment Test

- [ ] Python 3.10+ installed
- [ ] Virtual environment created
- [ ] `pip install -r requirements.txt` completed successfully
- [ ] `streamlit run app.py` opens the app in a browser
- [ ] `python app_cli.py` generates a Markdown report in `outputs/`
- [ ] `pytest` passes

## Functional Test

- [ ] Sample scenarios load in the sidebar
- [ ] Custom scenario text can be entered
- [ ] Risk findings update when scenario settings are changed
- [ ] CIA impact table displays correctly
- [ ] Risk register table displays correctly
- [ ] Risk score bar chart displays correctly
- [ ] Firewall recommendations display correctly
- [ ] IDS/IPS recommendations display correctly
- [ ] Vulnerability assessment recommendations display correctly
- [ ] SHA-256 and SHA3-256 digest outputs are generated
- [ ] HMAC output is generated
- [ ] AES-GCM encryption demo works after installing requirements
- [ ] Markdown report download works
- [ ] CSV risk register download works
- [ ] JSON result download works

## Submission Evidence

- [ ] GitHub repository created
- [ ] All files committed to GitHub
- [ ] README displays correctly on GitHub
- [ ] Screenshots captured for the report/handover document
- [ ] Exported report reviewed
- [ ] Acknowledgement of GAI Contribution added to final submission
- [ ] Student can explain risk scoring logic in the viva/handover meeting
