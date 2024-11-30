import dash
from dash import dcc
from dash import html
import plotly.express as px
import pandas as pd

# Sample data
df = pd.DataFrame({
    "Fruit": ["Apples", "Oranges", "Bananas", "Apples", "Oranges", "Bananas"],
    "Amount": [4, 1, 2, 2, 4, 5],
    "City": ["SF", "SF", "SF", "Montreal", "Montreal", "Montreal"]
})

# Initialize the app
app = dash.Dash(__name__)
server=app.server

# App layout
app.layout = html.Div([
    html.H1("Simple Plotly Dash App"),
    dcc.Graph(
        id='example-graph',
        figure=px.bar(df, x="Fruit", y="Amount", color="City", barmode="group")
    )
])

# Run the app
if __name__ == '__main__':
    app.run_server(debug=True)
