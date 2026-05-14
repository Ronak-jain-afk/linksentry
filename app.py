import os
import sys

import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from linksentry.predictor import predict_url, predict_urls, load_model, get_model_path
from linksentry.extractor import extract_features, FEATURE_ORDER, EXTERNAL_FEATURE_NAMES
from linksentry.model import load_manifest
from linksentry import __version__

st.set_page_config(
    page_title="LinkSentry",
    page_icon=":shield:",
    layout="centered",
)

PAGES = ["Single URL Check", "Batch Check", "Model Info", "Feature Explorer"]


def main():
    st.sidebar.title("LinkSentry")
    st.sidebar.caption(f"v{__version__}")
    page = st.sidebar.radio("Navigation", PAGES)

    if page == "Single URL Check":
        show_single_check()
    elif page == "Batch Check":
        show_batch_check()
    elif page == "Model Info":
        show_model_info()
    elif page == "Feature Explorer":
        show_feature_explorer()


def show_single_check():
    st.header("Single URL Check")
    url = st.text_input("URL", placeholder="https://example.com/login")
    col1, col2, col3 = st.columns(3)
    with col1:
        full = st.checkbox("Full analysis (DNS/WHOIS)")
    with col2:
        explain = st.checkbox("Show top features")
    with col3:
        check = st.button("Check", type="primary")

    if check and url:
        with st.spinner("Analyzing..."):
            result = predict_url(url, full=full, explain=explain)

        if result['label'] == 'error':
            st.error(f"Error: {result['error']}")
            return

        if result['label'] == 'phishing':
            st.error("Phishing Detected")
        else:
            st.success("Legitimate")

        col1, col2 = st.columns(2)
        conf = result['confidence'] * 100
        col1.metric("Confidence", f"{conf:.1f}%")
        col2.metric("Features Used", result['features_extracted'])

        st.progress(conf / 100, text="Confidence")

        with st.expander("Probability Breakdown", expanded=True):
            st.markdown(f"""
            - Legitimate: **{result['probability_legitimate']:.4f}**
            - Phishing: **{result['probability_phishing']:.4f}**
            """)

        if explain and result.get('top_features'):
            st.subheader("Top Features by Importance")
            for tf in result['top_features']:
                st.markdown(f"- **{tf['feature']}**: value={tf['value']}, importance={tf['importance']:.4f}")


def show_batch_check():
    st.header("Batch Check")
    uploaded = st.file_uploader("Upload a text file (one URL per line)", type=["txt"])
    col1, col2 = st.columns(2)
    with col1:
        full = st.checkbox("Full analysis (DNS/WHOIS)", key="batch_full")
    with col2:
        workers = st.slider("Parallel workers", 1, 8, 4)

    if uploaded is None:
        st.info("Upload a .txt file to begin.")
        return

    text = uploaded.getvalue().decode()
    urls = [line.strip() for line in text.splitlines() if line.strip()]

    if not urls:
        st.warning("No URLs found in file.")
        return

    st.write(f"Found **{len(urls)}** URLs")

    if st.button("Check All", type="primary"):
        progress_bar = st.progress(0, text="Starting...")
        status_text = st.empty()

        results = []
        total = len(urls)
        for i, url in enumerate(urls):
            try:
                r = predict_url(url, full=full)
            except Exception as e:
                r = {'url': url, 'label': 'error', 'error': str(e),
                     'confidence': None}
            results.append(r)
            progress = (i + 1) / total
            progress_bar.progress(progress, text=f"{i+1}/{total}")
            status_text.text(f"Checking: {url}")

        progress_bar.empty()
        status_text.empty()

        phishing = [r for r in results if r['label'] == 'phishing']
        legitimate = [r for r in results if r['label'] == 'legitimate']
        errors = [r for r in results if r['label'] == 'error']

        col1, col2, col3 = st.columns(3)
        col1.metric("Total", len(results))
        col2.metric("Phishing", len(phishing), delta_color="inverse")
        col3.metric("Errors", len(errors))

        if phishing:
            st.subheader("Phishing URLs")
            for r in phishing:
                conf = r.get('confidence', 0)
                if conf:
                    st.error(f"{r['url']} (confidence: {conf*100:.1f}%)")
                else:
                    st.error(r['url'])

        csv_lines = ["url,label,confidence"]
        for r in results:
            csv_lines.append(f"{r['url']},{r.get('label','')},{r.get('confidence','')}")
        csv_data = "\n".join(csv_lines)

        st.download_button(
            "Download Results (CSV)",
            data=csv_data,
            file_name="linksentry_results.csv",
            mime="text/csv",
        )


def show_model_info():
    st.header("Model Info")
    model_path = get_model_path(full=False)
    full_model_path = get_model_path(full=True)

    if not model_path.exists():
        st.warning("No model found. Train one with `linksentry train`.")
        return

    col1, col2 = st.columns(2)
    size_mb = round(model_path.stat().st_size / (1024 * 1024), 2)
    col1.metric("Model Size", f"{size_mb} MB")
    full_size = "N/A"
    if full_model_path.exists():
        full_size = f"{round(full_model_path.stat().st_size / (1024 * 1024), 2)} MB"
    col2.metric("Full Model Size", full_size)

    try:
        model = load_model(full=False)
        clf = model.named_steps.get('classifier')
        if clf:
            st.write(f"**Type:** {type(clf).__name__}")
            st.write(f"**Estimators:** {getattr(clf, 'n_estimators', 'N/A')}")
            st.write(f"**Features:** {getattr(clf, 'n_features_in_', 'N/A')}")

        manifest = load_manifest(str(model_path))
        if manifest:
            st.subheader("Manifest")
            st.json(manifest)

        with st.expander("Model Paths"):
            st.code(f"Basic: {model_path}\nFull:  {full_model_path}")
    except Exception as e:
        st.error(f"Could not load model: {e}")


def show_feature_explorer():
    st.header("Feature Explorer")
    url = st.text_input("URL", placeholder="https://example.com/path/file.txt?q=1",
                        key="fe_url")
    full = st.checkbox("Include external features", key="fe_full")

    if not url:
        st.info("Enter a URL to see its extracted features.")
        return

    features = extract_features(url, full=full)
    ordered = {k: features.get(k, -1) for k in FEATURE_ORDER}

    total = len(ordered)
    external_count = sum(1 for k in ordered if k in EXTERNAL_FEATURE_NAMES)
    st.write(f"**{total} features extracted** ({total - external_count} structural, "
             f"{external_count} external)")

    categories = {
        "URL Characters": [k for k in ordered if k.endswith('_url') and k not in EXTERNAL_FEATURE_NAMES],
        "Domain": [k for k in ordered if k.endswith('_domain') or k in (
            'qty_vowels_domain', 'domain_length', 'domain_in_ip', 'server_client_domain')],
        "Directory": [k for k in ordered if k.endswith('_directory') or k == 'directory_length'],
        "File": [k for k in ordered if k.endswith('_file') or k == 'file_length'],
        "Parameters": [k for k in ordered if k.endswith('_params') or k in (
            'params_length', 'tld_present_params', 'qty_params')],
        "Email/Shortener": ['email_in_url', 'url_shortened'],
        "External": list(EXTERNAL_FEATURE_NAMES),
    }

    tab_labels = [c for c in categories if any(k in ordered for k in categories[c])]
    tabs = st.tabs(tab_labels)

    for tab, label in zip(tabs, tab_labels):
        with tab:
            keys = [k for k in categories[label] if k in ordered]
            data = {k: ordered[k] for k in keys}
            import pandas as pd
            df = pd.DataFrame(list(data.items()), columns=["Feature", "Value"])
            df["Value"] = df["Value"].astype(str)
            st.dataframe(df, use_container_width=True, hide_index=True)


if __name__ == "__main__":
    main()
