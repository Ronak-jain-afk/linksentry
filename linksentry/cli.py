import json
import sys
import time
from pathlib import Path
from typing import Optional

import click

from . import __version__
from .extractor import extract_features, FEATURE_ORDER
from .predictor import predict_url, predict_urls, load_model, get_model_path
from .config import load_config, init_config, get_config_path
from .model import MODEL_TYPES, load_manifest
from .train import train_model


def format_result_text(result: dict) -> str:
    if result['label'] == 'phishing':
        icon = "⚠️  PHISHING"
        color = 'red'
    elif result['label'] == 'legitimate':
        icon = "✅ LEGITIMATE"
        color = 'green'
    else:
        icon = "❌ ERROR"
        color = 'yellow'
    
    lines = [
        click.style(f"\n{icon}", fg=color, bold=True),
        f"URL: {result['url']}",
    ]
    
    if result['error']:
        lines.append(click.style(f"Error: {result['error']}", fg='red'))
    else:
        conf_pct = result['confidence'] * 100
        lines.extend([
            f"Confidence: {conf_pct:.1f}%",
            f"P(Legitimate): {result['probability_legitimate']:.4f}",
            f"P(Phishing): {result['probability_phishing']:.4f}",
        ])
    
    if result.get('top_features'):
        lines.append("")
        lines.append(click.style("Top features by importance:", bold=True))
        for tf in result['top_features']:
            lines.append(
                f"  {tf['feature']:<30} value={tf['value']:<8}  importance={tf['importance']:.4f}"
            )
    
    return '\n'.join(lines)


@click.group()
@click.version_option(version=__version__, prog_name='LinkSentry')
def cli():
    """LinkSentry - Detect phishing URLs using machine learning."""
    pass


@cli.command()
@click.argument('url')
@click.option('--full', '-f', is_flag=True, help='Perform full feature extraction with DNS/WHOIS lookups')
@click.option('--explain', '-e', is_flag=True, help='Show top contributing features')
@click.option('--json', 'as_json', is_flag=True, help='Output result as JSON')
def check(url: str, full: bool, explain: bool, as_json: bool):
    """Check if a URL is phishing or legitimate."""
    try:
        result = predict_url(url, full=full, explain=explain)
    except FileNotFoundError as e:
        click.echo(click.style(f"Error: Model not found. Run 'linksentry train' first.", fg='red'), err=True)
        sys.exit(1)
    except Exception as e:
        result = {
            'url': url,
            'prediction': None,
            'label': 'error',
            'confidence': None,
            'probability_legitimate': None,
            'probability_phishing': None,
            'error': str(e)
        }
    
    if as_json:
        click.echo(json.dumps(result, indent=2))
    else:
        click.echo(format_result_text(result))
    
    if result['label'] == 'phishing':
        sys.exit(1)
    elif result['label'] == 'error':
        sys.exit(2)


@cli.command('check-file')
@click.argument('filepath', type=click.Path(exists=True))
@click.option('--full', '-f', is_flag=True, help='Perform full feature extraction with DNS/WHOIS lookups')
@click.option('--explain', '-e', is_flag=True, help='Show top contributing features')
@click.option('--json', 'as_json', is_flag=True, help='Output results as JSON')
@click.option('--output', '-o', type=click.Path(), help='Save results to CSV file')
def check_file(filepath: str, full: bool, explain: bool, as_json: bool, output: Optional[str]):
    """Check multiple URLs from a file (one URL per line)."""
    try:
        model = load_model(full=full)
    except FileNotFoundError:
        click.echo(click.style(f"Error: Model not found. Run 'linksentry train' first.", fg='red'), err=True)
        sys.exit(1)
    
    with open(filepath, 'r') as f:
        urls = [line.strip() for line in f if line.strip()]
    
    if not urls:
        click.echo(click.style("Error: No URLs found in file.", fg='red'), err=True)
        sys.exit(1)
    
    click.echo(f"Checking {len(urls)} URLs...")
    
    results = predict_urls(urls, model=model, full=full, explain=explain)
    
    phishing_count = sum(1 for r in results if r['label'] == 'phishing')
    legitimate_count = sum(1 for r in results if r['label'] == 'legitimate')
    error_count = sum(1 for r in results if r['label'] == 'error')
    
    if as_json:
        output_data = {
            'summary': {
                'total': len(results),
                'phishing': phishing_count,
                'legitimate': legitimate_count,
                'errors': error_count
            },
            'results': results
        }
        click.echo(json.dumps(output_data, indent=2))
    else:
        click.echo("\n" + "="*50)
        click.echo("RESULTS SUMMARY")
        click.echo("="*50)
        click.echo(f"Total URLs:  {len(results)}")
        click.echo(click.style(f"Phishing:    {phishing_count}", fg='red' if phishing_count > 0 else None))
        click.echo(click.style(f"Legitimate:  {legitimate_count}", fg='green' if legitimate_count > 0 else None))
        if error_count > 0:
            click.echo(click.style(f"Errors:      {error_count}", fg='yellow'))
        
        click.echo("\n" + "-"*50)
        for result in results:
            click.echo(format_result_text(result))
    
    if output:
        import pandas as pd
        df = pd.DataFrame(results)
        df.to_csv(output, index=False)
        click.echo(f"\nResults saved to: {output}")
    
    if phishing_count > 0:
        sys.exit(1)


@cli.command()
@click.argument('input', type=click.Path(exists=True))
@click.option('--output', '-o', required=True, type=click.Path(), help='Output CSV path')
@click.option('--full', '-f', is_flag=True, help='Perform full feature extraction with DNS/WHOIS lookups')
def extract(input: str, output: str, full: bool):
    """Extract features from URLs into a CSV for training.

    Reads URLs from INPUT (one per line), extracts all features,
    and writes them to OUTPUT as a CSV with a 'phishing' column (all 0).
    Edit the 'phishing' column with 0=legitimate, 1=phishing before training.
    """
    with open(input, 'r') as f:
        urls = [line.strip() for line in f if line.strip()]

    if not urls:
        click.echo(click.style("Error: No URLs found in file.", fg='red'), err=True)
        sys.exit(1)

    click.echo(f"Extracting features for {len(urls)} URLs...")

    total = len(urls)
    rows = []
    for i, url in enumerate(urls, 1):
        click.echo(f"  [{i}/{total}] {url}")
        try:
            features = extract_features(url, full=full)
            ordered = {key: features.get(key, -1) for key in FEATURE_ORDER}
            ordered['phishing'] = 0
            rows.append(ordered)
        except Exception as e:
            click.echo(click.style(f"    Error: {e}", fg='red'), err=True)

    if not rows:
        click.echo(click.style("Error: No features could be extracted.", fg='red'), err=True)
        sys.exit(1)

    import pandas as pd
    df = pd.DataFrame(rows)
    df.to_csv(output, index=False)
    click.echo(click.style(f"\nWrote {len(df)} rows to {output}", fg='green'))
    click.echo(f"Columns: {len(df.columns)} ({len(df.columns) - 1} features + 'phishing' target)")


@cli.command()
@click.option('--data', '-d', type=click.Path(exists=True), required=True, help='Path to training dataset CSV')
@click.option('--output', '-o', type=click.Path(), help='Path to save trained model')
@click.option('--model', '-m', type=click.Choice(MODEL_TYPES), default='rf', help='Model type (rf, xgb, lgb)')
@click.option('--full', '-f', is_flag=True, help='Train with external features (DNS/WHOIS) included')
def train(data: str, output: Optional[str], model: str, full: bool):
    """Train or retrain the phishing detection model."""
    try:
        result = train_model(data_path=data, output_path=output, full=full, model_type=model)
        click.echo(click.style("\nModel trained successfully!", fg='green', bold=True))
        click.echo(f"Model saved to: {result['model_path']}")
        click.echo(f"Accuracy: {result['metrics']['accuracy']:.4f}")
        if result['metrics']['roc_auc']:
            click.echo(f"ROC-AUC: {result['metrics']['roc_auc']:.4f}")
    except Exception as e:
        click.echo(click.style(f"Error during training: {e}", fg='red'), err=True)
        sys.exit(1)


@cli.command()
@click.option('--json', 'as_json', is_flag=True, help='Output as JSON')
def info(as_json: bool):
    """Show information about the installed model."""
    model_path = get_model_path()
    
    info_data = {
        'version': __version__,
        'model_path': str(model_path),
        'model_exists': model_path.exists(),
    }
    
    if model_path.exists():
        import os
        stat = model_path.stat()
        info_data['model_size_mb'] = round(stat.st_size / (1024 * 1024), 2)
        
        try:
            model = load_model()
            classifier = model.named_steps.get('classifier')
            if classifier:
                info_data['model_type'] = type(classifier).__name__
                info_data['n_estimators'] = getattr(classifier, 'n_estimators', None)
                info_data['n_features'] = getattr(classifier, 'n_features_in_', None)
        except Exception:
            pass
        
        manifest = load_manifest(str(model_path))
        if manifest:
            info_data['manifest'] = manifest
    
    if as_json:
        click.echo(json.dumps(info_data, indent=2))
    else:
        click.echo("\n" + "="*50)
        click.echo(click.style("LINKSENTRY INFO", bold=True))
        click.echo("="*50)
        click.echo(f"Version:      {info_data['version']}")
        click.echo(f"Model Path:   {info_data['model_path']}")
        
        if info_data['model_exists']:
            click.echo(click.style("Model Status: Installed", fg='green'))
            click.echo(f"Model Size:   {info_data.get('model_size_mb', 'N/A')} MB")
            click.echo(f"Model Type:   {info_data.get('model_type', 'N/A')}")
            click.echo(f"Estimators:   {info_data.get('n_estimators', 'N/A')}")
            click.echo(f"Features:     {info_data.get('n_features', 'N/A')}")
            
            manifest = info_data.get('manifest', {})
            if manifest:
                click.echo("")
                click.echo(click.style("Model Manifest:", bold=True))
                click.echo(f"  Trained at:  {manifest.get('trained_at', 'N/A')}")
                click.echo(f"  LinkSentry:  v{manifest.get('linksentry_version', 'N/A')}")
                click.echo(f"  Full mode:   {manifest.get('full', 'N/A')}")
                click.echo(f"  Accuracy:    {manifest.get('accuracy', 'N/A')}")
                if manifest.get('roc_auc'):
                    click.echo(f"  ROC-AUC:     {manifest['roc_auc']}")
        else:
            click.echo(click.style("Model Status: Not found", fg='red'))
            click.echo("Run 'linksentry train --data <dataset.csv>' to train a model.")


@cli.command()
@click.argument('filepath', type=click.Path(exists=True))
@click.option('--interval', '-i', default=300, type=int, help='Seconds between checks')
@click.option('--full', '-f', is_flag=True, help='Perform full feature extraction with DNS/WHOIS lookups')
def watch(filepath: str, interval: int, full: bool):
    """Watch URLs for changes in classification over time.

    Re-checks URLs from FILEPATH at regular INTERVAL and reports changes.
    """
    try:
        model = load_model(full=full)
    except FileNotFoundError:
        click.echo(click.style("Error: Model not found. Run 'linksentry train' first.", fg='red'), err=True)
        sys.exit(1)

    with open(filepath, 'r') as f:
        urls = [line.strip() for line in f if line.strip()]

    if not urls:
        click.echo(click.style("Error: No URLs found in file.", fg='red'), err=True)
        sys.exit(1)

    click.echo(click.style(f"\nWatching {len(urls)} URLs every {interval}s - Ctrl+C to stop", bold=True))
    click.echo("=" * 50)

    previous = {}
    total_changes = 0

    try:
        while True:
            now = time.strftime('%H:%M:%S')
            click.echo(f"\n[{now}] Checking {len(urls)} URLs...")

            results = predict_urls(urls, model=model, full=full)
            phishing_now = 0

            for r in results:
                url = r['url']
                label = r['label']
                prev_label = previous.get(url)

                if label == 'phishing':
                    phishing_now += 1

                if prev_label is not None and prev_label != label:
                    total_changes += 1
                    if label == 'phishing':
                        icon = click.style("CHANGED -> PHISHING", fg='red', bold=True)
                    else:
                        icon = click.style("CHANGED -> LEGITIMATE", fg='green', bold=True)
                    conf = r['confidence'] * 100
                    click.echo(f"  {icon}  {url}  (confidence: {conf:.1f}%)")
                elif prev_label is None:
                    status = click.style("PHISHING", fg='red') if label == 'phishing' else click.style("OK", fg='green')
                    click.echo(f"  [{status}] {url}")

                previous[url] = label

            click.echo(f"  Status: {len(urls) - phishing_now} legitimate, {phishing_now} phishing")

            click.echo(f"\n  -> Sleeping {interval}s... ", nl=False)
            time.sleep(interval)

    except KeyboardInterrupt:
        summary_line = "CHANGES DETECTED" if total_changes > 0 else "NO CHANGES"
        click.echo(f"\n\n{'=' * 50}")
        click.echo(click.style(f"WATCH COMPLETE - {summary_line}", bold=True))
        click.echo(f"Total reclassifications: {total_changes}")
        click.echo("=" * 50)


@cli.group()
def config():
    """Manage LinkSentry configuration."""
    pass


@config.command('init')
def config_init():
    """Create default configuration file."""
    path = init_config()
    click.echo(click.style(f"Config created: {path}", fg='green'))


@config.command('show')
def config_show():
    """Show current configuration."""
    cfg = load_config()
    path = cfg.pop('_path', '')
    click.echo(f"\nConfig file: {path}")
    click.echo("=" * 50)
    for section, values in cfg.items():
        click.echo(click.style(f"\n[{section}]", bold=True))
        for key, val in values.items():
            click.echo(f"  {key} = {val}")


def main():
    cli()


if __name__ == '__main__':
    main()
