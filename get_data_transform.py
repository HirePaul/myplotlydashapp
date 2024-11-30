import MySQLdb
import dash
from dash import dcc
from dash import html
from dash.dependencies import Input, Output
import pandas as pd
import plotly.express as px
import dash_bootstrap_components as dbc
import plotly.graph_objects as go
from dash import clientside_callback
import math
import requests
import geopandas as gpd
import matplotlib.pyplot as plt
import pycountry
import numpy as np
import statsmodels.api as sm
from statsmodels.formula.api import gls, ols
from statsmodels.stats.multicomp import pairwise_tukeyhsd
import io
from dash import dash_table
from scipy.stats import kruskal
from scipy.spatial.distance import pdist, squareform
from skbio.stats.distance import permanova, DistanceMatrix
import pingouin as pg
import plotly.figure_factory as ff
from scipy.stats import mannwhitneyu


def get_country_code(ip_address):
    url = f"https://ipinfo.io/{ip_address}/json"
    response = requests.get(url)
    data = response.json()
    return data.get("country")  # Returns the country code, e.g., "US"


db = MySQLdb.connect(host="honeypotresearches.mysql.database.azure.com", user="biggadminn", port=3306, passwd="BigMassiveCock", db="hacs_db_1")        # name of the data base

cur = db.cursor()

# Use all the SQL you like
cur.execute("SELECT * FROM session_info ")

external_stylesheets = [dbc.themes.BOOTSTRAP]


data=cur.fetchall()


db.close()
df = pd.DataFrame(data, columns=[desc[0] for desc in cur.description])

db = MySQLdb.connect(host="honeypotresearches.mysql.database.azure.com", user="biggadminn", port=3306, passwd="BigMassiveCock", db="hacs_db_1")        # name of the data base

cur = db.cursor()

# Use all the SQL you like
cur.execute("SELECT * FROM command_info ")

data=cur.fetchall()
commands_df = pd.DataFrame(data, columns=[desc[0] for desc in cur.description])

db.close()

df=df.drop_duplicates()


print("HERE")
print(commands_df.head())
print(commands_df.columns)

commands_df = commands_df.drop_duplicates()
print(df.columns)
my_count = df.shape[0]
my_ip_count = df["attacker_ip"].unique().shape[0]
df["num_commands"]=df["num_commands"].astype(int)


app = dash.Dash(__name__, external_stylesheets=external_stylesheets)

df.columns = ["Honeypot","Config","Iteration","Username","Password","IP","Fake_Time","Commands","LoginTime","Honeypot IP", "Time","Attack_Type"] 

df['Time'] = df['Time'].astype('float')

df=df[df["Time"]>0]





print(df["Time"].head())
sum_commands = df["Commands"].sum()
my_sum_commands = commands_df.shape[0]


def get_country_code_alpha3(ip_address):
    # Get the alpha-2 country code from ipinfo.io
    url = f"https://ipinfo.io/{ip_address}/json"
    response = requests.get(url)
    data = response.json()
    country_alpha2 = data.get("country")  # e.g., "US"
    

    # Convert to alpha-3 using pycountry
    try:
        country = pycountry.countries.get(alpha_2=country_alpha2)
        if country:
            return country.alpha_3  # e.g., "USA"
    except:
        return None  # Return None if conversion is not found
count=0
df["Country_Code"]=df["IP"]
df["Count"]=np.ones(len(df))
country_dict = {}
for ip in df["IP"].unique():
    count+=1
    country_code = get_country_code_alpha3(ip.strip())
    df.loc[df["IP"]==ip, "Country_Code"] = country_code
    if country_code not in country_dict.keys():
        country_dict[country_code]=1
    else:
        country_dict[country_code]=country_dict[country_code]+1
    
    if count==9:
        break

sum_by_category = df.groupby('Country_Code')['Count'].sum()


# Export as two lists
categories = sum_by_category.index.tolist()
values = sum_by_category.values.tolist()

world_df = pd.DataFrame({"countries":country_dict.keys(),"IP Count":country_dict.values()})

# Create the choropleth map
fig_world = px.choropleth(
    data_frame=world_df,
    locations="countries",       # Column with country ISO codes
    color='IP Count',             # Column to be color-coded
    hover_name='countries',      # Column for country names in hover text
    color_continuous_scale=["#333333","#E50D3C"],  # Color scale (options: Viridis, Inferno, etc.)
    labels={'value': 'Value'}  # Label for the color bar
)

# Update the layout for better display
fig_world.update_layout(
    title="Attacker IP Address Location",
    geo=dict(showframe=False, showcoastlines=False)  # Optional: Hide map borders
)
fig_world.update_layout(geo=dict(
        bgcolor="black",  # Set background color
        showcoastlines=False,  # Show coastlines
        coastlinecolor="white", # Set coastline color
        showland=False,       # Show landmass
        landcolor="#333333"  # Set land color
    ))

fig_world.update_layout(plot_bgcolor = 'black',paper_bgcolor="black",font_color = 'white')


fig_world.update_layout(
    margin=dict(l=30, r=0, t=75, b=0)  # Set padding/margins to 0 for max space usage
)
fig_world.update_geos(
    lataxis_range=[-60, 90]  # Set lower limit to -60 to exclude Antarctica
)




fig_all_attacks = px.violin(
    df,
    y='Time',
    x='Config',
    color='Config',  # Color by Configuration to differentiate configurations
    box=True,  # Draw box plot inside the violin
    points='all',  # Show all points
    title='Time Spent for All Attacks by Configuration',
    labels={'Config': 'Configuration', 'Time': 'Time Spent (s)'}
)
fig_all_attacks.update_layout(title_pad=dict(t=-200), plot_bgcolor = 'black',paper_bgcolor="black",font_color = 'white')
fig_all_attacks.update_layout(
    margin=dict(l=80, r=0, t=75, b=20)  # Set padding/margins to 0 for max space usage
)
fig_all_attacks.update_layout(
    yaxis=dict(
        range=[0, 25]  # Set the desired range
    )
)

df=df.sort_values("LoginTime")
df_unique_ips = df.drop_duplicates(subset='IP', keep='first')

fig_all_attacks_unique_time = px.violin(
    df_unique_ips,
    y='Time',
    x='Config',
    color='Config',  # Color by Configuration to differentiate configurations
    box=True,  # Draw box plot inside the violin
    points='all',  # Show all points
    title='Time Spent for Unique IP Attacks by Configuration',
    labels={'Config': 'Configuration', 'Time': 'Time Spent (s)'}
)
fig_all_attacks_unique_time.update_layout(title_pad=dict(t=-200), plot_bgcolor = 'black',paper_bgcolor="black",font_color = 'white')
fig_all_attacks_unique_time.update_layout(
    margin=dict(l=80, r=0, t=75, b=20)  # Set padding/margins to 0 for max space usage
)
fig_all_attacks_unique_time.update_layout(
    yaxis=dict(
        range=[0, 25]  # Set the desired range
    )
)

fig_all_attacks_commands = px.violin(
    df,
    y='Commands',
    x='Config',
    color='Config',  # Color by Configuration to differentiate configurations
    box=True,  # Draw box plot inside the violin
    points='all',  # Show all points
    title='Number of Commands Run for All Attacks by Configuration',
    labels={'Config': 'Configuration', 'Time': 'Time Spent (s)'}
)
fig_all_attacks_commands.update_layout(title_pad=dict(t=-200), plot_bgcolor = 'black',paper_bgcolor="black",font_color = 'white')
fig_all_attacks_commands.update_layout(
    margin=dict(l=80, r=0, t=75, b=20)  # Set padding/margins to 0 for max space usage
)
fig_all_attacks_commands.update_layout(
    yaxis=dict(
        range=[0, 5]  # Set the desired range
    )
)

fig_all_attacks_unique_commands = px.violin(
    df_unique_ips,
    y='Commands',
    x='Config',
    color='Config',  # Color by Configuration to differentiate configurations
    box=True,  # Draw box plot inside the violin
    points='all',  # Show all points
    title='Number of Commands Run for Unique IP Attacks by Configuration',
    labels={'Config': 'Configuration', 'Time': 'Time Spent (s)'}
)
fig_all_attacks_unique_commands.update_layout(title_pad=dict(t=-200), plot_bgcolor = 'black',paper_bgcolor="black",font_color = 'white')
fig_all_attacks_unique_commands.update_layout(
    margin=dict(l=80, r=0, t=75, b=20)  # Set padding/margins to 0 for max space usage
)
fig_all_attacks_unique_commands.update_layout(
    yaxis=dict(
        range=[0, 5]  # Set the desired range
    )
)




df=df.dropna()
df.loc[(df["Config"]%2)==0,"CPU"]="Higher"
df.loc[df["Config"]%2==1,"CPU"]="Lower"
df.loc[df["Config"]%8<=3,"Latency"]="1000ms"
df.loc[df["Config"]%8>=4,"Latency"]="0ms"
df.loc[df["Config"]<=7,"Bandwidth"]="Higher"
df.loc[df["Config"]>=8,"Bandwidth"]="Lower"
df.loc[((df["Config"]//2)%2)==0,"Memory"]="Higher"
df.loc[((df["Config"]//2)%2)==1,"Memory"]="Lower"
df["Time"]=df["Time"].astype(int)
formula = 'Time ~ C(CPU) * C(Latency) * C(Bandwidth) * C(Memory)'
stats_data=df[["CPU","Latency","Bandwidth","Memory","Time"]]
model = ols(formula, data=stats_data).fit()
anova_results = sm.stats.anova_lm(model, typ=2)  # typ=2 for main effects and interactions

df=df.sort_values("LoginTime")
df_unique_ips = df.drop_duplicates(subset='IP', keep='first')

formula = 'Time ~ C(CPU) * C(Bandwidth) * C(Memory)'
stats_data_2_1=df[df["Latency"]=="0ms"]
stats_data_2_1=stats_data_2_1[["CPU","Bandwidth","Memory","Time"]]
model = ols(formula, data=stats_data_2_1).fit()
anova_results_2_1 = sm.stats.anova_lm(model, typ=2)  # typ=2 for main effects and interactions

formula = 'Time ~ C(CPU) * C(Bandwidth) * C(Memory)'
stats_data_2_2=df[df["Latency"]=="1000ms"]
stats_data_2_2=stats_data_2_2[["CPU","Bandwidth","Memory","Time"]]
model = ols(formula, data=stats_data_2_2).fit()

formula = 'Time ~ C(CPU) * C(Bandwidth) * C(Memory)'
stats_data_3_1=df_unique_ips[df_unique_ips["Latency"]=="0ms"]
stats_data_3_1=stats_data_3_1[["CPU","Bandwidth","Memory","Time"]]

formula = 'Time ~ C(CPU) * C(Bandwidth) * C(Memory)'
stats_data_3_2=df_unique_ips[df_unique_ips["Latency"]=="1000ms"]
stats_data_3_2=stats_data_3_2[["CPU","Bandwidth","Memory","Time"]]

formula = 'Time ~ C(CPU) * C(Bandwidth) * C(Memory)'
stats_data_4_1=df[df["Latency"]=="0ms"]
stats_data_4_1=stats_data_4_1[["CPU","Bandwidth","Memory","Commands"]]

formula = 'Time ~ C(CPU) * C(Bandwidth) * C(Memory)'
stats_data_4_2=df[df["Latency"]=="1000ms"]
stats_data_4_2=stats_data_4_2[["CPU","Bandwidth","Memory","Commands"]]

formula = 'Time ~ C(CPU) * C(Bandwidth) * C(Memory)'
stats_data_5_1=df_unique_ips[df_unique_ips["Latency"]=="0ms"]
stats_data_5_1=stats_data_5_1[["CPU","Bandwidth","Memory","Commands"]]

formula = 'Time ~ C(CPU) * C(Bandwidth) * C(Memory)'
stats_data_5_2=df_unique_ips[df_unique_ips["Latency"]=="1000ms"]
stats_data_5_2=stats_data_5_2[["CPU","Bandwidth","Memory","Commands"]]

group_labels = ["No Latency","1s Latency"]

list1=df[(df["Latency"]=="0ms") & (df["Time"]<20)]["Time"].to_list()
list2=df[(df["Latency"]=="1000ms") & (df["Time"]<20)]["Time"].to_list()

my_new_curve = ff.create_distplot([list1,list2], group_labels, show_hist=False, show_rug=False, bin_size=.1)
my_new_curve.update_layout(xaxis_title="Time (s)", yaxis_title="Relative Frequency",title="Distribution Curve for No vs 1s Latency")
my_new_curve.update_layout(title_pad=dict(t=-200), plot_bgcolor = 'black',paper_bgcolor="black",font_color = 'white')
my_new_curve.update_layout(
    margin=dict(l=80, r=0, t=75, b=20)  # Set padding/margins to 0 for max space usage
)

list1=df_unique_ips[(df_unique_ips["Latency"]=="0ms") & (df_unique_ips["Time"]<20)]["Time"].to_list()
list2=df_unique_ips[(df_unique_ips["Latency"]=="1000ms") & (df_unique_ips["Time"]<20)]["Time"].to_list()
my_new_curve_unique = ff.create_distplot([list1,list2], group_labels, show_hist=False, show_rug=False, bin_size=.1)
my_new_curve_unique.update_layout(xaxis_title="Time (s)", yaxis_title="Relative Frequency",title="Distribution Curve for No vs 1s Latency")
my_new_curve_unique.update_layout(title_pad=dict(t=-200), plot_bgcolor = 'black',paper_bgcolor="black",font_color = 'white')
my_new_curve_unique.update_layout(
    margin=dict(l=80, r=0, t=75, b=20)  # Set padding/margins to 0 for max space usage
)

list1=df[(df["Latency"]=="0ms") & (df["Commands"]<20)]["Commands"].to_list()
list2=df[(df["Latency"]=="1000ms") & (df["Commands"]<20)]["Commands"].to_list()
my_new_curve_commands = ff.create_distplot([list1,list2], group_labels, show_hist=True, show_rug=False, bin_size=.1)
my_new_curve_commands.update_layout(xaxis_title="Commands", yaxis_title="Relative Frequency",title="Distribution Curve for No vs 1s Latency")
my_new_curve_commands.update_layout(title_pad=dict(t=-200), plot_bgcolor = 'black',paper_bgcolor="black",font_color = 'white')
my_new_curve_commands.update_layout(
    margin=dict(l=80, r=0, t=75, b=20)  # Set padding/margins to 0 for max space usage
)

list1=df_unique_ips[(df_unique_ips["Latency"]=="0ms") & (df_unique_ips["Commands"]<20)]["Commands"].to_list()
list2=df_unique_ips[(df_unique_ips["Latency"]=="1000ms") & (df_unique_ips["Commands"]<20)]["Commands"].to_list()
my_new_curve_commands_unique = ff.create_distplot([list1,list2], group_labels, show_hist=True, show_rug=False, bin_size=.1)
my_new_curve_commands_unique.update_layout(xaxis_title="Commands", yaxis_title="Relative Frequency",title="Distribution Curve for No vs 1s Latency")
my_new_curve_commands_unique.update_layout(title_pad=dict(t=-200), plot_bgcolor = 'black',paper_bgcolor="black",font_color = 'white')
my_new_curve_commands_unique.update_layout(
    margin=dict(l=80, r=0, t=75, b=20)  # Set padding/margins to 0 for max space usage
)



def getAnovaList(anova_results):
    anova_results["Independent Variable"]=anova_results.index
    anova_results["p-value"]=anova_results["PR(>F)"]
    anova_results = anova_results.dropna()
    anova_results["PR(>F)"]=anova_results["PR(>F)"].astype(float)
    indep=anova_results["Independent Variable"].to_list()
    pvalues=anova_results["p-value"].to_list()
    reg_anova_time_list = []
    round_floats = []
    for x in pvalues:
        round_floats.append(format(x, '.3e'))
    for i, x in enumerate(round_floats):
        reg_anova_time_list.append([indep[i],x])
    return reg_anova_time_list

print(anova_results)


latency_tukey_results = pairwise_tukeyhsd(endog=df['Time'], groups=df['Latency'], alpha=0.05)
cpu_tukey_results = pairwise_tukeyhsd(endog=df['Time'], groups=df['CPU'], alpha=0.05)
print(latency_tukey_results)

cpu_mann_results_1 = mannwhitneyu(df[(df["CPU"]=="Higher") & (df["Latency"]=="0ms")]["Time"],df[(df["CPU"]=="Lower") & (df["Latency"]=="0ms")]["Time"])
cpu_mann_results_2 = mannwhitneyu(df[(df["CPU"]=="Higher") & (df["Latency"]=="1000ms")]["Time"],df[(df["CPU"]=="Lower") & (df["Latency"]=="1000ms")]["Time"])
mann_results_1 = [["CPU Groups (No Latency)",format(cpu_mann_results_1.pvalue,'.3e')],["CPU Groups (1s Latency)",format(cpu_mann_results_2.pvalue,'.3e')]]

print(df["Commands"].value_counts())

Results=cpu_tukey_results
cpu_tukey_df = pd.DataFrame(data=Results._results_table.data[1:], columns=Results._results_table.data[0])
Results=latency_tukey_results
latency_tukey_df = pd.DataFrame(data=Results._results_table.data[1:], columns=Results._results_table.data[0])

def makeTukeyList(df):
    return [df["group1"].to_list()+df["group2"].to_list()+df["meandiff"].to_list()+df["p-adj"].to_list()+df["lower"].to_list()+df["upper"].to_list()+df["reject"].to_list()]

latency_tukey_df_list = makeTukeyList(latency_tukey_df)
cpu_tukey_df_list = makeTukeyList(cpu_tukey_df)
print(latency_tukey_df_list)
anova_results["Independent Variable"]=anova_results.index
anova_results["p-value"]=anova_results["PR(>F)"]
anova_results = anova_results.dropna()
anova_results["PR(>F)"]=anova_results["PR(>F)"].astype(float)
indep=anova_results["Independent Variable"].to_list()
pvalues=anova_results["p-value"].to_list()
reg_anova_time_list = []
round_floats = []
for x in pvalues:
    round_floats.append(format(x, '.3e'))
for i, x in enumerate(round_floats):
    reg_anova_time_list.append([indep[i],x])




reg_anova_time_list_2_1 = getAnovaList(anova_results_2_1)


data=df[["Time"]]
metadata=df[["Latency","CPU","Memory","Bandwidth"]]


# Compute distance matrix (e.g., Euclidean)
distance_matrix = pdist(data, metric='euclidean')
distance_matrix = squareform(distance_matrix)

# Create DistanceMatrix object
dm = DistanceMatrix(distance_matrix, ids=metadata.index)
result_main = permanova(dm, metadata, column="Memory", permutations=999)



# Print the result
print(result_main)


TEXT = {
    "font-size":"min(1.4vh,1vw)",
    "text-align":"center",
    "color":"white"
}

def getStyle(pvalue, alpha,TEXT):
    try:
        if (float(pvalue) < 0.05):
            TEXT["background-color"]="#E50D3C"
            return TEXT
        else:
            TEXT["background-color"]="black"
            return TEXT
    except:
            TEXT["background-color"]="black"
            return TEXT

def getStyleTukey(pvalue, alpha,TEXT):
    print(pvalue)
    print(type(pvalue))
    try:
        if (float(pvalue)=="True"):
            TEXT["background-color"]="#E50D3C"
            return TEXT
        if(pvalue==True):
            TEXT["background-color"]="#E50D3C"
            return TEXT
        else:
            TEXT["background-color"]="black"
            return TEXT
    except:
        if (pvalue==True):
            TEXT["background-color"]="#E50D3C"
        return TEXT

def makeAnovaTable(title,top_padding,anova_list, TEXT,TEXT_STYLE):
    return html.Div(dbc.Col([html.H1(title,style=TEXT_STYLE)] +
            [
                        dbc.Row(html.Div([html.Div(html.P(str(new_line[0]),style=TEXT),style={"width":"70%","background-color":"black","border":"0.1vh solid white","height":"3vh","margin":"0","padding":"0"}),
                                html.Div(html.P(str(new_line[1]),style=TEXT),style=getStyle(new_line[1],0.05,{"width":"30%","background-color":"red","border":"0.1vh solid white","height":"3vh","margin":"0","padding":"0"}))],style={"display":"flex","flex-direction":"row"}))
                        for new_line in anova_list],style={"padding":"min(2.5vh,1vw)","padding-top":str(top_padding)+"vh","height":"100%","width":"95%","margin-top":"-2.5%","display":"flex","flex-direction":"column"}),style={"width":"100%"})

def makeKruskalTable(title, anova_list, TEXT,TEXT_STYLE):
    anova_list = [["Independent Variable","p-value"]] + anova_list
    return html.Div(dbc.Col([html.H1(title,style=TEXT_STYLE)] +
            [
                        dbc.Row(html.Div([html.Div(html.P(str(new_line[0]),style=TEXT),style={"width":"70%","background-color":"black","border":"0.1vh solid white","height":"3vh","margin":"0","padding":"0"}),
                                html.Div(html.P(str(new_line[1]),style=TEXT),style=getStyle(new_line[1],0.05,{"width":"30%","background-color":"red","border":"0.1vh solid white","height":"3vh","margin":"0","padding":"0"}))],style={"display":"flex","flex-direction":"row"}))
                        for new_line in anova_list],style={"padding":"5%","height":"100%","width":"95%","margin-top":"-2.5%","display":"flex","flex-direction":"column"}),style={"width":"100%"})

def makeTukeyTable(anova_list, TEXT, TEXT_STYLE, variable):
    return dbc.Col([html.H1("Tukey HSD Results " +variable,style=TEXT_STYLE)] +
            [
                        dbc.Row(html.Div([html.Div(html.P(str(new_line[0]),style=TEXT),style={"width":"14%","background-color":"black","border":"0.1vh solid white","height":"3vh","margin":"0","padding":"0"}),
                                          html.Div(html.P(str(new_line[1]),style=TEXT),style={"width":"14%","background-color":"black","border":"0.1vh solid white","height":"3vh","margin":"0","padding":"0"}),
                                          html.Div(html.P(str(new_line[2]),style=TEXT),style={"width":"14%","background-color":"black","border":"0.1vh solid white","height":"3vh","margin":"0","padding":"0"}),
                                          html.Div(html.P(str(new_line[3]),style=TEXT),style={"width":"14%","background-color":"black","border":"0.1vh solid white","height":"3vh","margin":"0","padding":"0"}),
                                          html.Div(html.P(str(new_line[4]),style=TEXT),style={"width":"14%","background-color":"black","border":"0.1vh solid white","height":"3vh","margin":"0","padding":"0"}),
                                          html.Div(html.P(str(new_line[5]),style=TEXT),style={"width":"14%","background-color":"black","border":"0.1vh solid white","height":"3vh","margin":"0","padding":"0"}),
                                html.Div(html.P(str(new_line[6]),style=TEXT),style=getStyleTukey(new_line[6],0.05,{"width":"16%","background-color":"red","border":"0.1vh solid white","height":"3vh","margin":"0","padding":"0"}))],style={"display":"flex","flex-direction":"row"}))
                        for new_line in anova_list],style={"padding":"5%","height":"100%","width":"95%","margin-top":"-2.5%","display":"flex","flex-direction":"column"})

def makeMannTable(title, anova_list, TEXT,TEXT_STYLE):
    anova_list = [["Independent Variable","p-value"]] + anova_list
    return html.Div(dbc.Col([html.H1(title,style=TEXT_STYLE)] +
            [
                        dbc.Row(html.Div([html.Div(html.P(str(new_line[0]),style=TEXT),style={"width":"70%","background-color":"black","border":"0.1vh solid white","height":"3vh","margin":"0","padding":"0"}),
                                html.Div(html.P(str(new_line[1]),style=TEXT),style=getStyle(new_line[1],0.05,{"width":"30%","background-color":"red","border":"0.1vh solid white","height":"3vh","margin":"0","padding":"0"}))],style={"display":"flex","flex-direction":"row"}))
                        for new_line in anova_list],style={"padding":"5%","height":"100%","width":"95%","margin-top":"-2.5%","display":"flex","flex-direction":"column"}),style={"width":"100%"})

def makeCommandTable(title, anova_list, TEXT,TEXT_STYLE):
    anova_list = [["Command","Count"]] + anova_list
    return html.Div(dbc.Col([html.H1(title,style=TEXT_STYLE)] +
            [
                        dbc.Row(html.Div([html.Div(html.P(str(new_line[0]),style=TEXT),style={"width":"70%","background-color":"black","border":"0.1vh solid white","height":"3vh","margin":"0","padding":"0"}),
                                html.Div(html.P(str(new_line[1]),style=TEXT),style=getStyle(new_line[1],0.05,{"width":"30%","background-color":"red","border":"0.1vh solid white","height":"3vh","margin":"0","padding":"0"}))],style={"display":"flex","flex-direction":"row"}))
                        for new_line in anova_list],style={"padding":"5%","height":"100%","width":"95%","margin-top":"-2.5%","display":"flex","flex-direction":"column"}),style={"width":"100%"})


# Create a StringIO object
output = io.StringIO()

# Redirect the output of print to the StringIO object
print(anova_results, file=output)

# Get the value from the StringIO object
captured_output = output.getvalue()

# Example DataFrame format
# Assuming data has columns: 'Factor1', 'Factor2', 'Factor3', 'Factor4', and 'DependentVar'

# Run Kruskal-Wallis test for each factor individually
kw_factor1 = kruskal(*[group['Time'].values for name, group in df.groupby('CPU')])
kw_factor2 = kruskal(*[group['Time'].values for name, group in df.groupby('Latency')])
kw_factor3 = kruskal(*[group['Time'].values for name, group in df.groupby('Bandwidth')])
kw_factor4 = kruskal(*[group['Time'].values for name, group in df.groupby('Memory')])

print("pvalue of Kruskal-Wallis Test for CPU:", kw_factor1.pvalue)
print("pvalue of Kruskal-Wallis Test for Latency:", kw_factor2.pvalue)
print("pvalue of Kruskal-Wallis Test for Bandwidth:", kw_factor3.pvalue)
print("pvalue of Kruskal-Wallis Test for Memory:", kw_factor4.pvalue)

krusk_df_1 = pd.DataFrame({"Independent Variable":["CPU","Latency","Bandwidth","Memory"],"pvalue":[kw_factor1.pvalue,kw_factor2.pvalue,kw_factor3.pvalue,kw_factor4.pvalue]})

kw_list_1 = [["CPU",format(kw_factor1.pvalue, '.3e')],["Latency",format(kw_factor2.pvalue, '.3e')],["Bandwidth",format(kw_factor3.pvalue, '.3e')],["Memory",format(kw_factor4.pvalue, '.3e')]]

kw_factor1 = kruskal(*[group['Time'].values for name, group in stats_data_2_1.groupby('CPU')])
kw_factor3 = kruskal(*[group['Time'].values for name, group in stats_data_2_1.groupby('Bandwidth')])
kw_factor4 = kruskal(*[group['Time'].values for name, group in stats_data_2_1.groupby('Memory')])

kw_list_2 = [["CPU",format(kw_factor1.pvalue, '.3e')],["Bandwidth",format(kw_factor3.pvalue, '.3e')],["Memory",format(kw_factor4.pvalue, '.3e')]]


kw_factor1 = kruskal(*[group['Time'].values for name, group in stats_data_2_2.groupby('CPU')])
kw_factor3 = kruskal(*[group['Time'].values for name, group in stats_data_2_2.groupby('Bandwidth')])
kw_factor4 = kruskal(*[group['Time'].values for name, group in stats_data_2_2.groupby('Memory')])

kw_list_3 = [["CPU",format(kw_factor1.pvalue, '.3e')],["Bandwidth",format(kw_factor3.pvalue, '.3e')],["Memory",format(kw_factor4.pvalue, '.3e')]]


#unique
kw_factor1 = kruskal(*[group['Time'].values for name, group in stats_data_3_1.groupby('CPU')])
kw_factor3 = kruskal(*[group['Time'].values for name, group in stats_data_3_1.groupby('Bandwidth')])
kw_factor4 = kruskal(*[group['Time'].values for name, group in stats_data_3_1.groupby('Memory')])

kw_list_4 = [["CPU",format(kw_factor1.pvalue, '.3e')],["Bandwidth",format(kw_factor3.pvalue, '.3e')],["Memory",format(kw_factor4.pvalue, '.3e')]]


kw_factor1 = kruskal(*[group['Time'].values for name, group in stats_data_3_2.groupby('CPU')])
kw_factor3 = kruskal(*[group['Time'].values for name, group in stats_data_3_2.groupby('Bandwidth')])
kw_factor4 = kruskal(*[group['Time'].values for name, group in stats_data_3_2.groupby('Memory')])

kw_list_5 = [["CPU",format(kw_factor1.pvalue, '.3e')],["Bandwidth",format(kw_factor3.pvalue, '.3e')],["Memory",format(kw_factor4.pvalue, '.3e')]]


#commands
kw_factor1 = kruskal(*[group['Commands'].values for name, group in stats_data_4_1.groupby('CPU')])
kw_factor3 = kruskal(*[group['Commands'].values for name, group in stats_data_4_1.groupby('Bandwidth')])
kw_factor4 = kruskal(*[group['Commands'].values for name, group in stats_data_4_1.groupby('Memory')])

kw_list_6 = [["CPU",format(kw_factor1.pvalue, '.3e')],["Bandwidth",format(kw_factor3.pvalue, '.3e')],["Memory",format(kw_factor4.pvalue, '.3e')]]

kw_factor1 = kruskal(*[group['Commands'].values for name, group in stats_data_4_2.groupby('CPU')])
kw_factor3 = kruskal(*[group['Commands'].values for name, group in stats_data_4_2.groupby('Bandwidth')])
kw_factor4 = kruskal(*[group['Commands'].values for name, group in stats_data_4_2.groupby('Memory')])

kw_list_7 = [["CPU",format(kw_factor1.pvalue, '.3e')],["Bandwidth",format(kw_factor3.pvalue, '.3e')],["Memory",format(kw_factor4.pvalue, '.3e')]]

kw_factor1 = kruskal(*[group['Commands'].values for name, group in stats_data_5_1.groupby('CPU')])
kw_factor3 = kruskal(*[group['Commands'].values for name, group in stats_data_5_1.groupby('Bandwidth')])
kw_factor4 = kruskal(*[group['Commands'].values for name, group in stats_data_5_1.groupby('Memory')])

kw_list_8 = [["CPU",format(kw_factor1.pvalue, '.3e')],["Bandwidth",format(kw_factor3.pvalue, '.3e')],["Memory",format(kw_factor4.pvalue, '.3e')]]

kw_factor1 = kruskal(*[group['Commands'].values for name, group in stats_data_5_2.groupby('CPU')])
kw_factor3 = kruskal(*[group['Commands'].values for name, group in stats_data_5_2.groupby('Bandwidth')])
kw_factor4 = kruskal(*[group['Commands'].values for name, group in stats_data_5_2.groupby('Memory')])

kw_list_9 = [["CPU",format(kw_factor1.pvalue, '.3e')],["Bandwidth",format(kw_factor3.pvalue, '.3e')],["Memory",format(kw_factor4.pvalue, '.3e')]]

print(kw_list_6)

print(commands_df["short_command"].value_counts().head(10))
commands_list_1=commands_df["short_command"].value_counts().head(20).index.tolist()
commands_list_2=commands_df["short_command"].value_counts().head(20).values.tolist()

final_commands_list=[]
for i, command in enumerate(commands_list_1):
    final_commands_list.append([command,commands_list_2[i]])
    


header_percent_left=1
header_padding="0% 0% 0% "+str(header_percent_left)+"%"
header_y_percent=10
sidebar_x_percent=15
main_x_percent=100 - sidebar_x_percent
main_y_percent=100 - header_y_percent
padding_percent_right=1
padding_percent_left=2
padding_percent_top=0.5
padding=str(padding_percent_top)+"% "+str(padding_percent_right)+"% "+str(padding_percent_top)+"% "+str(padding_percent_left)+"%"
header_y=str(header_y_percent)+"%"
sidebar_x=str(sidebar_x_percent)+"%"
sidebar_x_right=str(sidebar_x_percent+padding_percent_right+padding_percent_left)+"%"
main_x=str(main_x_percent)+"%"
main_y=str(main_y_percent)+"%"
font="Verdana, Helvetica, sans-serif"
header_style = {
    "position":"fixed",
    "left":"0",
    "top":"0",
    "background-color": "#0f0f0f",
    "width":"100%",
    "height":header_y,
    "margin":"0",
    "font-family":font,
    "padding": header_padding,
    "font-size":"100%",
    "content": "",
    "display": "inline-block",
}

side_bar = {
    "position":"fixed",
    "background-color": "purple",
    "width":sidebar_x,
    "left":"0",
    "top":header_y,
    "height":"100vh",
    "margin":"0",
    "font-family":font
    
}

main_content = {
    "position":"fixed",
    "background-color":"black",
    "left":sidebar_x_right,
    "top":header_y,
    "font-family":font,
    "width":main_x,
    "height":main_y,
    "padding":"0 0.75% 0 0"
}


SIDEBAR_STYLE = {
    "position": "fixed",
    "top": header_y,
    "left": 0,
    "bottom": 0,
    "width": sidebar_x_right,
    "padding": padding,
    "background-color": "#0f0f0f",
    "font-family":font
}

navlink_style = {
    "font-family":font,
    "font-size":"min(4vh,2.5vw)",
    "padding":"2% 2% 2% 2%",
    "margin-left":"2%",
    "margin-right":"5%",
    "margin-top":"-3%",
    "margin-bottom":"2%",
    "text-decoration":"none",
    "color":"gray",
    "font-weight": "400",
    "text-align":"left",
    "padding":"5%",
}

navlink_div_style = {
    "font-family":font,
    "margin":"2% 2% 2% 2%"
}

# the styles for the main content position it to the right of the sidebar and
# add some padding.
CONTENT_STYLE = {
    "margin-left": sidebar_x,
    "margin-right": "2rem",
    "padding": "2rem 1rem",
}

TEXT_STYLE = {
    "margin-top":"2%",
    "font-family":font,
    "font-size":"min(4vh,2.5vw)",
    "color":"white",
    "font-weight": "500",
    "margin-bottom":"0.7vh"
}

TEXT_STYLE_TEST = {
    "margin-top":"2%",
    "font-family":font,
    "font-size":"min(1vh,0.7vw)",
    "color":"white",
    "font-weight": "500"
}

test = html.Div([html.H1("mytester")],className="mytest")

sidebar = html.Div(
    [
        dcc.Location(id='url', refresh=False),
        html.H2("Analysis Type", className="display-4",style=TEXT_STYLE),
        html.Hr(style={"background-color":"#899EEE","height":"0.5vw","width":"110%","opacity":".8","margin-top":"4%","margin-left":"-0.5vw"}),
        dbc.Nav(
            [
                html.Div([dbc.NavLink("General", href="/", active="exact",style=navlink_style)],style=navlink_div_style),
                html.Div([dbc.NavLink("Time", href="/timeanalysis", active="exact",style=navlink_style)],style=navlink_div_style),
                html.Div([dbc.NavLink("Unique IP Time", href="/uniquetimeanalysis", active="exact",style=navlink_style)],style=navlink_div_style),
                html.Div([dbc.NavLink("Command", href="/commandanalysis", active="exact",style=navlink_style)],style=navlink_div_style),
                html.Div([dbc.NavLink("Unique IP Command", href="/uniquecommandanalysis", active="exact",style=navlink_style)],style=navlink_div_style),
                html.Div([dbc.NavLink("Conclusion", href="/conclusion", active="exact",style=navlink_style)],style=navlink_div_style),
            ],
            vertical=True,
            pills=True,
        ),
    ],
    style=SIDEBAR_STYLE,
)

print(anova_results.columns)
anova_results["Independent Variable"]=anova_results.index
anova_results["p-value"]=anova_results["PR(>F)"]
anova_results = anova_results.dropna()
anova_results["PR(>F)"]=anova_results["PR(>F)"].astype(float)
table = html.Div([
    html.H1("ANOVA Results",style={"color":"white","font-size":"min(4vh,2.5vw)"}),
    dash_table.DataTable(
        id='anova-table',
        columns=[{"name": "Independent Variable", "id": "Independent Variable"}, {"name": "p-value", "id":"p-value"}],
        data=anova_results.to_dict('records'),
        style_table={'height':"100%",'width': '100%', "background-color":"black","overflow":"auto"},
        style_cell={'textAlign': 'center',"font-size":"1.3vh","background-color":"black","color":"white"},
        style_header={'fontWeight': 'bold'},
        style_data_conditional=[
             {
                'if': {
                    'filter_query': '{p-value} < 0.05',
                    'column_id': 'p-value'
                },
                'backgroundColor': '#E50D3C',
                'color': 'white',
                'fontWeight': 'bold'
            }
        ]
    )
],style={"padding":"5%"})




table2 = html.Div([
    html.H1("Tukey HSD (Latency)",style={"color":"white","font-size":"min(4vh,2.5vw)"}),
    dash_table.DataTable(
        id='hsd-table-1',
        columns=[{"name": col, "id": col} for col in latency_tukey_df.columns],
        data=latency_tukey_df.to_dict('records'),
        style_table={'height':"100%",'width': '100%', "background-color":"black","overflow":"auto"},
        style_cell={'textAlign': 'center',"font-size":"1.3vh","background-color":"black","color":"white"},
        style_header={'fontWeight': 'bold'},
        style_data_conditional=[
            {
            'if': {
                'filter_query': '{reject} contains "true"',
                'column_id': 'reject'
            },
            'backgroundColor': '#E50D3C',
            'color': 'white',
                'fontWeight': 'bold'
        }
        ]
    )
],style={"padding":"5%","height":"10%"})


table3 = html.Div([
    html.H1("Tukey HSD (CPU)",style={"color":"white","font-size":"min(4vh,2.5vw)"}),
    dash_table.DataTable(
        id='hsd-table-2',
        columns=[{"name": col, "id": col} for col in cpu_tukey_df.columns],
        data=cpu_tukey_df.to_dict('records'),
        style_table={'height':"100%",'width': '100%', "background-color":"black","overflow":"auto"},
        style_cell={'textAlign': 'center',"font-size":"1.3vh","background-color":"black","color":"white"},
        style_header={'fontWeight': 'bold'},
        style_data_conditional=[
            {
            'if': {
                'filter_query': '{reject} contains "true"',
                'column_id': 'reject'
            },
            'backgroundColor': '#E50D3C',
            'color': 'white',
                'fontWeight': 'bold'
        }
        ]
    )
],style={"padding":"5%","height":"20%"})

table4 = html.Div([
    html.H1("Kruskal-Wallis Results",style={"color":"white","font-size":"min(4vh,2.5vw)"}),
    dash_table.DataTable(
        id='hsd-table-2',
        columns=[{"name": col, "id": col} for col in krusk_df_1.columns],
        data=krusk_df_1.to_dict('records'),
        style_table={'height':"100%",'width': '100%', "background-color":"black","overflow":"auto"},
        style_cell={'textAlign': 'center',"font-size":"1.3vh","background-color":"black","color":"white"},
        style_header={'fontWeight': 'bold'},
        style_data_conditional=[
            {
            'if': {
                'filter_query': '{pvalue} < 0.05',
                'column_id': 'pvalue'
            },
            'backgroundColor': '#E50D3C',
            'color': 'white',
                'fontWeight': 'bold'
        }
        ]
    )
],style={"padding":"5%","height":"20%"})


table_attempt = html.Div(
    style={
        'height': '50vh',         # Container height (e.g., 50% of viewport height)
        'width': '100%',          # Full width of the viewport
        'border': '1px solid black',  # Optional border for visibility
        'overflow': 'hidden',     # Prevent overflow
        'display': 'flex',
        'justifyContent': 'center',
        'alignItems': 'center',
    },
    children=[
        html.Table(
            # Add a header row
            [html.Tr([html.Th(col) for col in anova_results.columns])] +
            # Add data rows
            [html.Tr([html.Td(anova_results.iloc[i][col]) for col in anova_results.columns]) for i in range(len(anova_results))],
            style={
                'width': '90%',                # Set table width to fit container
                'textAlign': 'center',         # Center text alignment
                'borderCollapse': 'collapse',  # Collapse borders for a cleaner look
                'fontSize': '16px',            # Adjust font size if needed
            },
            # Optional inline CSS for table cells
            className='my-table'
        )
    ]
)




header = html.Header(children=[
                            html.H1(children =
                                    ['UMD HACS 200 Group 2I Dashboard'],
                                    style={"color": "white","font-size":"min("+str(int(header_y_percent/4*2))+"vh"+",5vw)","margin-top":str(int(header_y_percent/8*1))+"%"})],
                                    style=header_style)
select = html.Div(children = [
                            html.H1(children=
                                    ["Select Graph"])]
                            ,style=side_bar)

graph = html.Div(children= [dcc.Graph(id='responsive-graph-2',figure=fig_world,responsive=True,style={"width":"95%","height":"100%","font-size":"5vh"})])
graph3 = html.Div(children= [dcc.Graph(id='responsive-graph',figure=fig_all_attacks,config={'responsive': True},style={"height":"100%","width":"95%","margin":"auto"})])
graph4 = html.Div(children= [dcc.Graph(id='responsive-graph-3',figure=my_new_curve,config={'responsive': True},style={"height":"100%","width":"95%","margin":"auto"})])
graph5 = html.Div(children= [dcc.Graph(id='responsive-graph-4',figure=my_new_curve_unique,config={'responsive': True},style={"height":"100%","width":"95%","margin":"auto"})])
graph6 = html.Div(children= [dcc.Graph(id='responsive-graph-5',figure=my_new_curve_commands,config={'responsive': True},style={"height":"100%","width":"95%","margin":"auto"})])
graph7 = html.Div(children= [dcc.Graph(id='responsive-graph-6',figure=my_new_curve_commands_unique,config={'responsive': True},style={"height":"100%","width":"95%","margin":"auto"})])


content = html.Div(id="page-content", style=CONTENT_STYLE)
#dbc.Col(makeCommandTable("Top 10 Commands",final_commands_list,TEXT,TEXT_STYLE),width=4.5,style={"margin-left":"3vw","width":"25vw","margin-top":"5vh"}),
#dbc.Col(html.P("Graph Filter  ",style={"color":"white","text-align":"right","font-size":"min(4vh,2.5vw)","line-height":"10vh","margin-right":"2vw"}),width=4),
graph_test = dbc.Col(
            [dbc.Row(
                    [
                        dbc.Col(
                            [dbc.Row(
                                [html.H2("Attacks",style={"color":"white","font-size":"min(4vh,2.5vw)","text-align":"center"}),
                                html.H2(str(my_count),style={"color":"#E50D3C","font-size":"min(4vh,2.5vw)","margin-top":"-2vh","text-align":"center","font-family":font})],
                                style={"margin-left":"1.5vw",'height': '30%',"width":"100%","background-color":"black","margin":"2vh","border-left": "1vh outset #E50D3C"}),
                                dbc.Row(
                                [html.H2("Unique IPs",style={"color":"white","font-size":"min(4vh,2.5vw)","text-align":"center"}),
                                html.H2(str(my_ip_count),style={"color":"#E50D3C","font-size":"min(4vh,2.5vw)","margin-top":"-2vh","text-align":"center","font-family":font})],
                                style={"margin-left":"1.5vw",'height': '30%',"width":"100%","background-color":"black","margin":"2vh","border-left": "1vh outset #E50D3C"}),
                                dbc.Row(
                                [html.H2("Commands",style={"color":"white","font-size":"min(4vh,2.5vw)","text-align":"center"}),
                                html.H2(str(my_sum_commands),style={"color":"#E50D3C","font-size":"min(4vh,2.5vw)","margin-top":"-2vh","text-align":"center","font-family":font})],
                                style={"margin-left":"1.5vw",'height': '30%',"width":"100%","background-color":"black","margin":"2vh","border-left": "1vh outset #E50D3C"})
                            ],width=3,style={'height': str(int((main_y_percent*2/5)))+"vh","margin-top":"0.75%","margin-left":"2vw"}
                        ), dbc.Col(
                            dbc.Row(
                                graph,style={"height":"100%","width":"100%"}
                            ),style={'height': str(int((main_y_percent*2/5)))+"vh","margin-top":"0.75%"}, width=8),
                        ],style={"width":"100%"}),
                        dbc.Row(
                            [
                             dbc.Col([
                                 dbc.Row([
                                     
                                     dbc.Col(html.Div([dcc.Dropdown(['Time', 'Unique IP Time', 'Number of Commands','Unique IP Number of Commands'], 'Time', id='demo-dropdown',style={"border-left": "1vh solid white","color":"white","backgroundColor":"black"})],
                                     style={"left":"0vw","margin":"1vh","height":"10vh","margin-bottom":"2vh"})
                        )],style={"height":"10vh","margin-left":"2vw","margin-top":"4vh","margin-bottom":"-2vh"}),
                        dbc.Row(
                            graph3, style={"height":str(int((main_y_percent*3.1/8)))+"vh","width":"99%"}
                        )])
                    ],style={})], style=main_content)

graph_test_6 = dbc.Col(
            [
                dbc.Col(makeCommandTable("Top 20 Commands",final_commands_list,TEXT,TEXT_STYLE),width=4.5,style={"margin-left":"3vw","width":"25vw","margin-top":"5vh"}),
                dbc.Col([html.Div([html.H1("What do these fancy tests mean?",style=TEXT_STYLE),
                                                        html.P("The p-value tells you the probability that the data observed occured\
                                                               given that the null hypothesis is actually true. \n For our first (no latency) Kruskal-Wallis Test, our p-value of "+str(kw_list_4[1][1])+"\
                                                               means that there is a "+str(format(float(kw_list_4[1][1])*100,'.3e'))+"% probability that our data occurs in this manner\
                                                               given that there is no significant difference between\
                                                               the median attacker connection times for no latency configurations with a 256 kbit banwdith \
                                                                and a 2048kbit bandwidth.\
                                                               Since our p-value of "+str(kw_list_4[1][1])+" is much lower than our alpha of 0.05 (accepted threshhold),\
                                                               we reject the null hypothesis and support that there is a significant difference between the median attacker \
                                                               connection times for no latency configurations with a CPU and a \
                                                                CPU that has half the computing time.\
                                                                For our second (1s  latency) Kruskal-Wallis Test, our p-value of "+str(kw_list_5[0][1])+"\
                                                               means that there is a "+str(format(float(kw_list_5[0][1])*100,'.3e'))+"% probability that our data occurs in this manner\
                                                               given that there is no significant difference between the median attacker connection times for 1 second latency configurations with a CPU and a \
                                                                CPU that has half the computing time.\
                                                               Since our p-value of "+str(kw_list_5[0][1])+" is much lower than our alpha of 0.05 (accepted threshhold),\
                                                               we reject the null hypothesis and support that there is a significant difference between the median attacker\
                                                               connection times for 1 second latency configurations with a CPU and a \
                                                                CPU that has half the computing time.\
                                                                For all of our other tests, the p-value is above the threshold, so we fail to reject our null hypotheses.\
                                                               ",style={"color":"white","font-size":"min(2.5vh,1vw)","overflowY":"scroll","height":"75vh"})])],width=4)





             ],style=main_content)

text2="For our ANOVA tests (see note about Kruskal-Wallis at end), the null hypotheses are: \nH0 (RAM, no latency): There is no difference in the mean of the time spent in the honeypot\
                                                                for configurations with 3GB and 1GB of RAM for configurations with no additional latency\
                                                                H0 (RAM, 1s latency): There is no difference in the mean of the time spent in the honeypot\
                                                                for configurations with 3GB and 1GB of RAM for configurations with 1s additional latency\
                                                                \nH0 (CPU, no latency):\
                                                                There is no difference in the mean of the time spent\
                                                                in the honeypot for configurations with a CPU and a CPU that has half the computing time and no additional latency\
                                                                \nH0 (CPU, 1s latency):\
                                                                There is no difference in the mean of the time spent\
                                                                in the honeypot for configurations with a CPU and a CPU that has half the computing time and 1s additional latency\
                                                                H0 (Bandwidth, no latency): There is no difference in the mean of the time spent\
                                                                in the honeypot for configurations with a 256kbit upload and download speed and a 2048kbit upload and download speed for configurations with \
                                                                no additional latency\n\
                                                                H0 (Bandwidth, 1s latency): There is no difference in the mean of the time spent\
                                                                in the honeypot for configurations with a 256kbit upload and download speed and a 2048kbit upload and download speed for configurations with \
                                                                1s additional latency\n\
                                                                For ANOVA tests, the alternate hypotheses are: \
                                                                \nHa (RAM, no latency): The mean of the time spent in the honeypot\
                                                                for configurations with 3GB of RAM and no additional latency is greater than the configurations with 1GB of RAM and no additional latency\
                                                                \nHa (RAM, 1s latency): The mean of the time spent in the honeypot\
                                                                for configurations with 3GB of RAM and 1s additional latency is greater than the configurations with 1GB of RAM and 1s additional latency\
                                                                \nHa (CPU, no latency): The mean of the time spent\
                                                                in the honeypot for configurations with a CPU is greater than the configurations with a CPU that has half the computing time for configurations with no additional latency\
                                                                \nHa (CPU, 1s latency): The mean of the time spent\
                                                                in the honeypot for configurations with a CPU is greater than the configurations with a CPU that has half the computing time for configurations with 1s additional latency\
                                                                Ha (Bandwidth, no latency): The mean of the time spent\
                                                                in the honeypot for configurations with a 1024bit upload and download speed is greater than the configurations with a 256kbit upload and download speed for configurations with no additional latency\n\
                                                                Ha (Bandwidth, 1s latency): The mean of the time spent\
                                                                in the honeypot for configurations with a 1024bit upload and download speed is greater than the configurations with a 256kbit upload and download speed for configurations with 1s additional latency\n\n\
                                                                Note that for the Kruskal-Wallis tests, the hypotheses are the same, but instead of using the mean of the time, we are using the median.\
                                                                "
text1="Since the data for each configuration is NOT normally distributed, we cannot run ANOVA tests because they require the assumption that the data is normally distributed.\
We also cannot run tests based on latency, as the tests for latency have fundamentally different distributions, which we can see in the graph above.\
Our only option left is to run Kruskal-Wallis tests (non-parametric) on the other 3 independent variables that we have.\n\
For our Kruskal-Wallis tests, the null hypotheses are: \n\nH0 (RAM, no latency): There is no difference in the median of the time spent in the honeypot\
for configurations with 3GB and 1GB of RAM for configurations with no additional latency\
H0 (RAM, 1s latency): There is no difference in the median of the time spent in the honeypot\
for configurations with 3GB and 1GB of RAM for configurations with 1s additional latency\
\nH0 (CPU, no latency):\
There is no difference in the median of the time spent\
in the honeypot for configurations with a CPU and a CPU that has half the computing time and no additional latency\
\nH0 (CPU, 1s latency):\
There is no difference in the median of the time spent\
in the honeypot for configurations with a CPU and a CPU that has half the computing time and 1s additional latency\
H0 (Bandwidth, no latency): There is no difference in the median of the time spent\
in the honeypot for configurations with a 256kbit upload and download speed and a 2048kbit upload and download speed for configurations with \
no additional latency\n\
H0 (Bandwidth, 1s latency): There is no difference in the median of the time spent\
in the honeypot for configurations with a 256kbit upload and download speed and a 2048kbit upload and download speed for configurations with \
1s additional latency\n\
For the Kruskal-Wallis tests, the alternate hypotheses are: \
\nHa (RAM, no latency): The median of the time spent in the honeypot\
for configurations with 3GB of RAM and no additional latency is greater than the configurations with 1GB of RAM and no additional latency\
\nHa (RAM, 1s latency): The median of the time spent in the honeypot\
for configurations with 3GB of RAM and 1s additional latency is greater than the configurations with 1GB of RAM and 1s additional latency\
\nHa (CPU, no latency): The median of the time spent\
in the honeypot for configurations with a CPU is greater than the configurations with a CPU that has half the computing time for configurations with no additional latency\
\nHa (CPU, 1s latency): The median of the time spent\
in the honeypot for configurations with a CPU is greater than the configurations with a CPU that has half the computing time for configurations with 1s additional latency\
Ha (Bandwidth, no latency): The median of the time spent\
in the honeypot for configurations with a 1024bit upload and download speed is greater than the configurations with a 256kbit upload and download speed for configurations with no additional latency\n\
Ha (Bandwidth, 1s latency): The median of the time spent\
in the honeypot for configurations with a 1024bit upload and download speed is greater than the configurations with a 256kbit upload and download speed for configurations with 1s additional latency\n\n\
Note that we do not do any post-hoc tests because we only have two groups for each factor, so a post-hoc tests would just give the same p-value."

text2="For our ANOVA tests, the null hypotheses are: \nH0 (RAM):    There is no difference in the mean of the time spent in the honeypot\
                                                                for configurations with 3GB and 1GB of RAM\nH0 (CPU):    There is no difference in the mean of the time spent\
                                                                in the honeypot for configurations with a CPU and a CPU that has half the computing time\nH0 (Latency):    There is no\
                                                                difference in the mean of the time spent in the honeypot for configurations with a 1000 ms additional latency and no additional latency\n\
                                                                H0 (Bandwidth): There is no difference in the mean of the time spent\
                                                                in the honeypot for configurations with a 256kbit upload and download speed and a 2048kbit upload and download speed\n\
                                                                For ANOVA tests, the alternate hypotheses are: \nHa (RAM): There mean of the time spent in the honeypot\
                                                                for configurations with 3GB of RAM is greater than the configurations with 1GB of RAM\nHa (CPU): The mean of the time spent\
                                                                in the honeypot for configurations with a CPU is greater than the configurations with a CPU that has half the computing time\nHa (Latency): The\
                                                                mean of the time spent in the honeypot for configurations with no additional latency is greater than the configurations with 1000 ms additional latency\n\
                                                                Ha (Bandwidth): The mean of the time spent\
                                                                in the honeypot for configurations with a 1024bit upload and download speed is greater than the configurations with a 256kbit upload and download speed\n\n\
                                                                Note that for the Kruskal-Wallis tests, the hypotheses are the same, but instead of using the mean of the time, we are using the median.\
                                                                "   
'''
# [html.P(line,style={"color":"white","font-size":"min(2vw,2vh)"}) for line in text1.split('\n')]
graph_test_2 = html.Div(dbc.Row(
                    [
                        dbc.Col([dbc.Row(makeAnovaTable("PERMANOVA Results (Latency: 0s)",2.5,reg_anova_time_list_2_1,TEXT,TEXT_STYLE)),
                                 dbc.Row(makeAnovaTable("PERMANOVA Results (Latency: 1s)",1,reg_anova_time_list_2_2,TEXT,TEXT_STYLE)),
                                 html.Div([html.P(text1,style={"font-size":"min(2.5vh,1vw)","color":"white",'whiteSpace': 'pre-wrap'})],style={"overflowY":"scroll","height":"20vh","padding":"min(2.5vh,1vw)"}),
                                 ],width=3),
                        dbc.Col(
                            [html.Div(
                                [dbc.Col([dbc.Row(makeKruskalTable("bla",kw_list_2,TEXT,TEXT_STYLE)),
                                          dbc.Row(makeKruskalTable("bla",kw_list_3,TEXT,TEXT_STYLE)),
                                          makeTukeyTable(latency_tukey_df_list,TEXT,TEXT_STYLE,"(Latency)"),
                                          ],style={'height': str(int((main_y_percent*2/5)))+"%"})])],width=3),
                    
                        dbc.Col([html.Div([html.H1("What do these fancy tests mean?",style=TEXT_STYLE),
                                                        html.P("The p-value tells you the probability that the data observed occured\
                                                               given that the null hypothesis is actually true. Our p-value of .41258\
                                                               means that there is a 41.258% probability that our data occurs in this manner\
                                                               given that there is no significant difference between the means of the three locations.\
                                                               Since our p-value of .41258... is much higher than our alpha of 0.05 (accepted threshhold),\
                                                               we fail to reject the null hypothesis and support that there is no significant difference between\
                                                               the mean temperatures of the three locations (Beltsville, New York, Philadelphia).",style={"color":"white"})])],width=4),],
                        style=main_content,
                ),style=main_content)

graph_test_3 = html.Div(dbc.Row(
                    [
                        dbc.Col([dbc.Row(makeAnovaTable("PERMANOVA Results (Latency: 0s)",2.5,reg_anova_time_list_3_1,TEXT,TEXT_STYLE)),
                                 dbc.Row(makeAnovaTable("PERMANOVA Results (Latency: 1s)",1,reg_anova_time_list_3_2,TEXT,TEXT_STYLE)),
                                 html.Div([html.P(text1,style={"font-size":"min(2.5vh,1vw)","color":"white",'whiteSpace': 'pre-wrap'})],style={"overflowY":"scroll","height":"20vh","padding":"min(2.5vh,1vw)"}),
                                 ],width=3),
                        dbc.Col(
                            [html.Div(
                                [dbc.Col([dbc.Row(makeKruskalTable("bla",kw_list_4,TEXT,TEXT_STYLE)),
                                          dbc.Row(style={"height":"20vh"}),
                                          dbc.Row(makeKruskalTable("bla",kw_list_5,TEXT,TEXT_STYLE)),
                                          makeTukeyTable(latency_tukey_df_list,TEXT,TEXT_STYLE,"(Latency)"),
                                          ],style={'height': str(int((main_y_percent*2/5)))+"%"})])],width=3),
                    
                        dbc.Col([html.Div([html.H1("What do these fancy tests mean?",style=TEXT_STYLE),
                                                        html.P("The p-value tells you the probability that the data observed occured\
                                                               given that the null hypothesis is actually true. Our p-value of .41258\
                                                               means that there is a 41.258% probability that our data occurs in this manner\
                                                               given that there is no significant difference between the means of the three locations.\
                                                               Since our p-value of .41258... is much higher than our alpha of 0.05 (accepted threshhold),\
                                                               we fail to reject the null hypothesis and support that there is no significant difference between\
                                                               the mean temperatures of the three locations (Beltsville, New York, Philadelphia).",style={"color":"white"})])],width=4),],
                        style=main_content,
                ),style=main_content)
'''
graph_test_2 = html.Div(dbc.Row(
                    [
                        dbc.Col([dbc.Row(graph4,style={"height":"30vh"}),
                                 html.Div([html.P(text1,style={"font-size":"min(2.5vh,1vw)","color":"white",'whiteSpace': 'pre-wrap'})],style={"margin-top":"2vh","overflowY":"scroll","height":"55vh","padding":"min(2.5vh,1vw)"}),
                                 ],width=4),
                        dbc.Col(
                            [html.Div(
                                [dbc.Col([dbc.Row(makeKruskalTable("Kruskal-Wallis Tests (0s Latency)",kw_list_2,TEXT,TEXT_STYLE)),
                                          dbc.Row(makeKruskalTable("Kruskal-Wallis Tests (1s Latency)", kw_list_3,TEXT,TEXT_STYLE)),
                                          ],style={'height': str(int((main_y_percent*2/5)))+"%"})])],width=3),
                    
                        dbc.Col([html.Div([html.H1("What do these fancy tests mean?",style=TEXT_STYLE),
                                                        html.P("The p-value tells you the probability that the data observed occured\
                                                               given that the null hypothesis is actually true. For our first (no latency) Kruskal-Wallis Test, our p-value of "+str(kw_list_2[0][1])+"\
                                                               means that there is a "+str(format(float(kw_list_2[0][1])*100,'.3e'))+"% probability that our data occurs in this manner\
                                                               given that there is no significant difference between\
                                                               the median attacker connection times for no latency configurations with a CPU and a \
                                                                CPU that has half the computing time.\
                                                               Since our p-value of "+str(kw_list_2[0][1])+" is much lower than our alpha of 0.05 (accepted threshhold),\
                                                               we reject the null hypothesis and support that there is a significant difference between the median attacker \
                                                               connection times for no latency configurations with a CPU and a \
                                                                CPU that has half the computing time.\n\
                                                                For our first (no  latency) Kruskal-Wallis Test, our p-value of "+str(kw_list_2[2][1])+"\
                                                               means that there is a "+str(format(float(kw_list_2[2][1])*100,'.3e'))+"% probability that our data occurs in this manner\
                                                               given that there is no significant difference between the median attacker connection times for no latency configurations with a higher\
                                                               amount of RAM and a lower amount of RAM.\
                                                               Since our p-value of "+str(kw_list_3[2][1])+" is lower than our alpha of 0.05 (accepted threshhold),\
                                                               we reject the null hypothesis and support that there is a significant difference between the median attacker\
                                                               connection times for no latency configurations with a higher amount of RAM \
                                                                and a lower amount of RAM.\n\
                                                                For our second (1s  latency) Kruskal-Wallis Test, our p-value of "+str(kw_list_3[0][1])+"\
                                                               means that there is a "+str(format(float(kw_list_3[0][1])*100,'.3e'))+"% probability that our data occurs in this manner\
                                                               given that there is no significant difference between the median attacker connection times for 1 second latency configurations with a CPU and a \
                                                                CPU that has half the computing time.\
                                                               Since our p-value of "+str(kw_list_3[0][1])+" is much lower than our alpha of 0.05 (accepted threshhold),\
                                                               we reject the null hypothesis and support that there is a significant difference between the median attacker\
                                                               connection times for 1 second latency configurations with a CPU and a \
                                                                CPU that has half the computing time.\
                                                                For all of our other tests, the p-value is above the threshold, so we fail to reject our null hypotheses.\
                                                               ",style={"color":"white","font-size":"min(2.5vh,1vw)","overflowY":"scroll","height":"75vh"})])],width=4),],
                        style=main_content,
                ),style=main_content)

graph_test_3 = html.Div(dbc.Row(
                    [
                        dbc.Col([dbc.Row(graph5,style={"height":"30vh"}),
                                 html.Div([html.P(text1,style={"font-size":"min(2.5vh,1vw)","color":"white",'whiteSpace': 'pre-wrap'})],style={"margin-top":"2vh","overflowY":"scroll","height":"55vh","padding":"min(2.5vh,1vw)"}),
                                 ],width=4),
                        dbc.Col(
                            [html.Div(
                                [dbc.Col([dbc.Row(makeKruskalTable("Kruskal-Wallis Tests (0s Latency)",kw_list_4,TEXT,TEXT_STYLE)),
                                          dbc.Row(makeKruskalTable("Kruskal-Wallis Tests (1s Latency)", kw_list_5,TEXT,TEXT_STYLE)),
                                          ],style={'height': str(int((main_y_percent*2/5)))+"%"})])],width=3),
                    
                        dbc.Col([html.Div([html.H1("What do these fancy tests mean?",style=TEXT_STYLE),
                                                        html.P("The p-value tells you the probability that the data observed occured\
                                                               given that the null hypothesis is actually true. \n For our first (no latency) Kruskal-Wallis Test, our p-value of "+str(kw_list_4[0][1])+"\
                                                               means that there is a "+str(format(float(kw_list_4[0][1])*100,'.3e'))+"% probability that our data occurs in this manner\
                                                               given that there is no significant difference between\
                                                               the median attacker connection times for no latency configurations with a CPU and a \
                                                                CPU that has half the computing time.\
                                                               Since our p-value of "+str(kw_list_4[0][1])+" is much lower than our alpha of 0.05 (accepted threshhold),\
                                                               we reject the null hypothesis and support that there is a significant difference between the median attacker \
                                                               connection times for no latency configurations with a CPU and a \
                                                                CPU that has half the computing time.\
                                                                For our second (1s  latency) Kruskal-Wallis Test, our p-value of "+str(kw_list_5[0][1])+"\
                                                               means that there is a "+str(format(float(kw_list_5[0][1])*100,'.3e'))+"% probability that our data occurs in this manner\
                                                               given that there is no significant difference between the median attacker connection times for 1 second latency configurations with a CPU and a \
                                                                CPU that has half the computing time.\
                                                               Since our p-value of "+str(kw_list_5[0][1])+" is much lower than our alpha of 0.05 (accepted threshhold),\
                                                               we reject the null hypothesis and support that there is a significant difference between the median attacker\
                                                               connection times for 1 second latency configurations with a CPU and a \
                                                                CPU that has half the computing time.\
                                                                For all of our other tests, the p-value is above the threshold, so we fail to reject our null hypotheses.\
                                                               ",style={"color":"white","font-size":"min(2.5vh,1vw)","overflowY":"scroll","height":"75vh"})])],width=4),],
                        style=main_content,
                ),style=main_content)

graph_test_4 = html.Div(dbc.Row(
                    [
                        dbc.Col([dbc.Row(graph6,style={"height":"30vh"}),
                                 html.Div([html.P(text1,style={"font-size":"min(2.5vh,1vw)","color":"white",'whiteSpace': 'pre-wrap'})],style={"margin-top":"2vh","overflowY":"scroll","height":"55vh","padding":"min(2.5vh,1vw)"}),
                                 ],width=4),
                        dbc.Col(
                            [html.Div(
                                [dbc.Col([dbc.Row(makeKruskalTable("Kruskal-Wallis Tests (0s Latency)",kw_list_6,TEXT,TEXT_STYLE)),
                                          dbc.Row(makeKruskalTable("Kruskal-Wallis Tests (1s Latency)", kw_list_7,TEXT,TEXT_STYLE)),
                                          ],style={'height': str(int((main_y_percent*2/5)))+"%"})])],width=3),
                    
                        dbc.Col([html.Div([html.H1("What do these fancy tests mean?",style=TEXT_STYLE),
                                                        html.P("The p-value tells you the probability that the data observed occured\
                                                               given that the null hypothesis is actually true. \n \
                                                                For our second (1s  latency) Kruskal-Wallis Test, our p-value of "+str(kw_list_7[0][1])+"\
                                                               means that there is a "+str(format(float(kw_list_7[0][1])*100,'.3e'))+"% probability that our data occurs in this manner\
                                                               given that there is no significant difference between the median attacker connection times for 1 second latency configurations with a CPU and a \
                                                                CPU that has half the computing time.\
                                                               Since our p-value of "+str(kw_list_7[0][1])+" is much lower than our alpha of 0.05 (accepted threshhold),\
                                                               we reject the null hypothesis and support that there is a significant difference between the median attacker\
                                                               connection times for 1 second latency configurations with a CPU and a \
                                                                CPU that has half the computing time.\
                                                                For all of our other tests, the p-value is above the threshold, so we fail to reject our null hypotheses.\
                                                               ",style={"color":"white","font-size":"min(2.5vh,1vw)","overflowY":"scroll","height":"75vh"})])],width=4),],
                        style=main_content,
                ),style=main_content)

graph_test_5 = html.Div(dbc.Row(
                    [
                        dbc.Col([dbc.Row(graph7,style={"height":"30vh"}),
                                 html.Div([html.P(text1,style={"font-size":"min(2.5vh,1vw)","color":"white",'whiteSpace': 'pre-wrap'})],style={"margin-top":"2vh","overflowY":"scroll","height":"55vh","padding":"min(2.5vh,1vw)"}),
                                 ],width=4),
                        dbc.Col(
                            [html.Div(
                                [dbc.Col([dbc.Row(makeKruskalTable("Kruskal-Wallis Tests (0s Latency)",kw_list_8,TEXT,TEXT_STYLE)),
                                          dbc.Row(makeKruskalTable("Kruskal-Wallis Tests (1s Latency)", kw_list_9,TEXT,TEXT_STYLE)),
                                          ],style={'height': str(int((main_y_percent*2/5)))+"%"})])],width=3),
                    
                        dbc.Col([html.Div([html.H1("What do these fancy tests mean?",style=TEXT_STYLE),
                                                        html.P("The p-value tells you the probability that the data observed occured\
                                                               given that the null hypothesis is actually true. \n For our first (no latency) Kruskal-Wallis Test, our p-value of "+str(kw_list_4[1][1])+"\
                                                               means that there is a "+str(format(float(kw_list_4[1][1])*100,'.3e'))+"% probability that our data occurs in this manner\
                                                               given that there is no significant difference between\
                                                               the median attacker connection times for no latency configurations with a 256 kbit banwdith \
                                                                and a 2048kbit bandwidth.\
                                                               Since our p-value of "+str(kw_list_4[1][1])+" is much lower than our alpha of 0.05 (accepted threshhold),\
                                                               we reject the null hypothesis and support that there is a significant difference between the median attacker \
                                                               connection times for no latency configurations with a CPU and a \
                                                                CPU that has half the computing time.\
                                                                For our second (1s  latency) Kruskal-Wallis Test, our p-value of "+str(kw_list_5[0][1])+"\
                                                               means that there is a "+str(format(float(kw_list_5[0][1])*100,'.3e'))+"% probability that our data occurs in this manner\
                                                               given that there is no significant difference between the median attacker connection times for 1 second latency configurations with a CPU and a \
                                                                CPU that has half the computing time.\
                                                               Since our p-value of "+str(kw_list_5[0][1])+" is much lower than our alpha of 0.05 (accepted threshhold),\
                                                               we reject the null hypothesis and support that there is a significant difference between the median attacker\
                                                               connection times for 1 second latency configurations with a CPU and a \
                                                                CPU that has half the computing time.\
                                                                For all of our other tests, the p-value is above the threshold, so we fail to reject our null hypotheses.\
                                                               ",style={"color":"white","font-size":"min(2.5vh,1vw)","overflowY":"scroll","height":"75vh"})])],width=4),],
                        style=main_content,
                ),style=main_content)



app.layout = html.Div([dcc.Store(id="window-size", storage_type="session"),
                       dcc.Store(id="base-figure", data=fig_all_attacks.to_dict()),
                       dcc.Store(id="base-figure-2", data=fig_world.to_dict()),
                       dcc.Store(id="base-figure-3", data=my_new_curve.to_dict()),
                       dcc.Store(id="base-figure-3-unique", data=my_new_curve_unique.to_dict()),
                       dcc.Store(id="base-figure-3-commands", data=my_new_curve_unique.to_dict()),
                       dcc.Store(id="base-figure-3-commands-unique", data=my_new_curve_unique.to_dict()),
                       dcc.Store(id="base-figure-unique-ips-1", data=fig_all_attacks_unique_time.to_dict()),
                       dcc.Store(id="base-figure-commands-1", data=fig_all_attacks_commands.to_dict()),
                       dcc.Store(id="base-figure-commands-unique-ips-1", data=fig_all_attacks_unique_commands.to_dict()),
                       

    content,header,sidebar,
html.Div(style={"position":"absolute","height":"1vh","width":"100vw","top":"9vh","background-color":"#899EEE","opacity":".8",}),
                       html.Div(id="resize-listener", style={"display": "none"}),  # Hidden div for triggering resize event
dcc.Interval(id="interval", interval=7000, n_intervals=0)])

clientside_callback(
    """
    function(n_intervals) {
        return {width: window.innerWidth, height: window.innerHeight};
    }
    """,
    Output("window-size", "data"),
    Input("interval", "n_intervals")
)



@app.callback(Output('page-content', 'children'), [Input('url', 'pathname')])
def render_page_content(pathname):
    if pathname == "/":
        return graph_test
    elif pathname == "/timeanalysis":
        return graph_test_2
    elif pathname == "/uniquetimeanalysis":
        return graph_test_3
    elif pathname == "/commandanalysis":
        return graph_test_4
    elif pathname == "/uniquecommandanalysis":
        return graph_test_5
    elif pathname == "/conclusion":
        return graph_test_6
    # If the user tries to reach a different page, return a 404 message
    return html.Div(
        [
            html.H1("404: Not found", className="text-danger"),
            html.Hr(),
            html.P(f"The pathname {pathname} was not recognised..."),
        ],
        className="p-3 bg-light rounded-3",
    )


# Python callback to display window dimensions
@app.callback(
    Output("responsive-graph", "figure"),
    Input("window-size", "data"),
    Input("base-figure", "data"),
    Input('demo-dropdown', 'value'),
    Input("base-figure-unique-ips-1", "data"),
    Input("base-figure-commands-1", "data"),
    Input("base-figure-commands-unique-ips-1", "data")
)
def update_graph_font_size(window_size, stored_figure,value,stored_figure_unique_ips,stored_figure_commands,stored_figure_commands_unique_ips):
    # Convert the stored figure data back to a Plotly figure
    if (value=="Time"):
        fig = go.Figure(stored_figure)
    elif (value=="Unique IP Time"):
        fig = go.Figure(stored_figure_unique_ips)
    elif (value=="Number of Commands"):
        fig = go.Figure(stored_figure_commands)
    elif (value=="Unique IP Number of Commands"):
        fig = go.Figure(stored_figure_commands_unique_ips)
    else:
        fig=go.Figure(stored_figure)
    print("aaa")
    print(value)
    # Adjust font size based on window width
    if window_size is None:
        font_size = 14  # Default font size if window size not detected
    else:
        font_size = (window_size['height'] // 100 * 3)

    # Update only the font size in the figure's layout
    for trace in fig.data:
        if isinstance(trace, go.Violin):
            trace.update(marker=dict(size=1.0002**math.sqrt(window_size['height']*window_size['width'])))  # Update marker size for each violin trace
    fig.update_layout({"uirevision": "foo"}, legend=dict(font={"size": font_size/2}), font={"size": font_size})
    fig.update_layout(margin=dict(l=font_size*2, r=0, t=4.5*font_size, b=0))
    return fig

@app.callback(
    Output("responsive-graph-2", "figure"),
    Input("window-size", "data"),
    Input("base-figure-2", "data")
)
def update_graph_font_size(window_size, stored_figure):
    # Convert the stored figure data back to a Plotly figure
    fig = go.Figure(stored_figure)
    print("aaa")
    # Adjust font size based on window width
    if window_size is None:
        font_size = 14  # Default font size if window size not detected
    else:
        font_size = (window_size['height'] // 100 * 3)

    # Update only the font size in the figure's layout
    fig.update_layout({"uirevision": "foo"}, legend=dict(font={"size": font_size/2}), font={"size": font_size})
    fig.update_layout(margin=dict(l=0, r=0, t=3*font_size, b=0))
    return fig

@app.callback(
    Output("responsive-graph-3", "figure"),
    Input("window-size", "data"),
    Input("base-figure-3", "data")
)
def update_graph_font_size(window_size, stored_figure):
    # Convert the stored figure data back to a Plotly figure
    fig = go.Figure(stored_figure)
    # Adjust font size based on window width
    if window_size is None:
        font_size = 7.5  # Default font size if window size not detected
    else:
        font_size = (window_size['height'] // 100 * 1.8)

    # Update only the font size in the figure's layout
    fig.update_layout({"uirevision": "foo"}, legend=dict(font={"size": font_size}), font={"size": font_size})
    return fig

@app.callback(
    Output("responsive-graph-4", "figure"),
    Input("window-size", "data"),
    Input("base-figure-3-unique", "data")
)
def update_graph_font_size(window_size, stored_figure):
    # Convert the stored figure data back to a Plotly figure
    fig = go.Figure(stored_figure)
    # Adjust font size based on window width
    if window_size is None:
        font_size = 7.5  # Default font size if window size not detected
    else:
        font_size = (window_size['height'] // 100 * 1.8)

    # Update only the font size in the figure's layout
    fig.update_layout({"uirevision": "foo"}, legend=dict(font={"size": font_size}), font={"size": font_size})
    return fig


@app.callback(
    Output("responsive-graph-5", "figure"),
    Input("window-size", "data"),
    Input("base-figure-3-commands", "data")
)
def update_graph_font_size(window_size, stored_figure):
    # Convert the stored figure data back to a Plotly figure
    fig = go.Figure(stored_figure)
    # Adjust font size based on window width
    if window_size is None:
        font_size = 7.5  # Default font size if window size not detected
    else:
        font_size = (window_size['height'] // 100 * 1.8)

    # Update only the font size in the figure's layout
    fig.update_layout({"uirevision": "foo"}, legend=dict(font={"size": font_size}), font={"size": font_size})
    return fig


@app.callback(
    Output("responsive-graph-6", "figure"),
    Input("window-size", "data"),
    Input("base-figure-3-commands-unique", "data")
)
def update_graph_font_size(window_size, stored_figure):
    # Convert the stored figure data back to a Plotly figure
    fig = go.Figure(stored_figure)
    # Adjust font size based on window width
    if window_size is None:
        font_size = 7.5  # Default font size if window size not detected
    else:
        font_size = (window_size['height'] // 100 * 1.8)

    # Update only the font size in the figure's layout
    fig.update_layout({"uirevision": "foo"}, legend=dict(font={"size": font_size}), font={"size": font_size})
    return fig
    



if __name__ == '__main__':
    app.run_server(debug=False)
