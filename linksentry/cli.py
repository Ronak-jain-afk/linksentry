import json
import sys
from pathlib import Path
from typing import Optional

import click

from . import __version__
from .predictor import predict_url, predict_urls, load_model, get_model_path
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
    
    return '\n'.join(lines)


@click.group()
@click.version_option(version=__version__, prog_name='LinkSentry')
def cli():
    """LinkSentry - Detect phishing URLs using machine learning."""
    pass


@cli.command()
@click.argument('url')
@click.option('--full', '-f', is_flag=True, help='Perform full feature extraction with DNS/WHOIS lookups')
@click.option('--json', 'as_json', is_flag=True, help='Output result as JSON')
def check(url: str, full: bool, as_json: bool):
    """Check if a URL is phishing or legitimate."""
    try:
        result = predict_url(url, full=full)
        result['error'] = None
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
@click.option('--json', 'as_json', is_flag=True, help='Output results as JSON')
@click.option('--output', '-o', type=click.Path(), help='Save results to CSV file')
def check_file(filepath: str, full: bool, as_json: bool, output: Optional[str]):
    """Check multiple URLs from a file (one URL per line)."""
    try:
        model = load_model()
    except FileNotFoundError:
        click.echo(click.style(f"Error: Model not found. Run 'linksentry train' first.", fg='red'), err=True)
        sys.exit(1)
    
    with open(filepath, 'r') as f:
        urls = [line.strip() for line in f if line.strip()]
    
    if not urls:
        click.echo(click.style("Error: No URLs found in file.", fg='red'), err=True)
        sys.exit(1)
    
    click.echo(f"Checking {len(urls)} URLs...")
    
    results = predict_urls(urls, model=model, full=full)
    
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
@click.option('--data', '-d', type=click.Path(exists=True), required=True, help='Path to training dataset CSV')
@click.option('--output', '-o', type=click.Path(), help='Path to save trained model')
def train(data: str, output: Optional[str]):
    """Train or retrain the phishing detection model."""
    try:
        result = train_model(data_path=data, output_path=output)
        click.echo(click.style("\n✅ Model trained successfully!", fg='green', bold=True))
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
    
    if as_json:
        click.echo(json.dumps(info_data, indent=2))
    else:
        click.echo("\n" + "="*50)
        click.echo(click.style("LINKSENTRY INFO", bold=True))
        click.echo("="*50)
        click.echo(f"Version:      {info_data['version']}")
        click.echo(f"Model Path:   {info_data['model_path']}")
        
        if info_data['model_exists']:
            click.echo(click.style("Model Status: ✅ Installed", fg='green'))
            click.echo(f"Model Size:   {info_data.get('model_size_mb', 'N/A')} MB")
            click.echo(f"Model Type:   {info_data.get('model_type', 'N/A')}")
            click.echo(f"Estimators:   {info_data.get('n_estimators', 'N/A')}")
            click.echo(f"Features:     {info_data.get('n_features', 'N/A')}")
        else:
            click.echo(click.style("Model Status: ❌ Not found", fg='red'))
            click.echo("Run 'linksentry train --data <dataset.csv>' to train a model.")


def main():
    cli()


if __name__ == '__main__':
    main()
