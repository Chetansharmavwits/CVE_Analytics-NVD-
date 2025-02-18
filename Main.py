import streamlit as st
import pandas as pd
from transformers import pipeline
from Utils.data_extraction import CVE_Extraction, json_to_excel
from Utils import sematic_classification
from streamlit_extras.metric_cards import style_metric_cards
from st_aggrid import AgGrid, GridOptionsBuilder, GridUpdateMode
from datetime import datetime
import shutil
import os
from streamlit_extras.app_logo import add_logo
from dotenv import load_dotenv
import plotly.express as px
import plotly.subplots as sp



load_dotenv()
api_key = os.getenv("api_key")
keywords_file = os.getenv("keywords_file")
source_path = os.getenv("source_path")
destination_path = os.getenv("destination_path")


st.set_page_config(page_title="Analytics Dashboard", page_icon="🌎", layout="wide")
st.title("📈 CVE Analytics Dashboard ")

with open('style.css') as f:
    st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

st.logo("Icon/CVE_Icon.png", size="large")
st.sidebar.header("CVE Analysis Parameter")
upload_file = st.sidebar.file_uploader("Upload a Json Config File", type="json")
placeholder = st.empty()
button_1_col, button_2_col = st.sidebar.columns(2)
button_1 = button_1_col.button("Analysis Component Json")
button_2 = button_2_col.button("Semantic Data Analysis")
metrics_placeholder = st.empty()


def display_keywords(keyword_dict):
    df = pd.DataFrame({"Type": list(keyword_dict.keys()), "Keywords": [",".join(words) for words in keyword_dict.values()]})
    st.dataframe(df, use_container_width=True, hide_index=True)

def process_missing_data(actual_missing_data_file,index = 0):
    #Configure the Dataframe 
    st.write('Missing Data Table')
    missing_df = pd.read_excel(actual_missing_data_file)

    gb = GridOptionsBuilder.from_dataframe(missing_df)
    gb.configure_default_column(editable=True)
    gb.configure_column("File Name",editable=False)
    gb.configure_selection("single")
    grid_options = gb.build()
    
    # Display the grid
    grid_response = AgGrid(
        missing_df,
        gridOptions=grid_options,
        update_mode=GridUpdateMode.VALUE_CHANGED,
        height=500,
        width="100%",
        enable_enterprise_modules=False,
        )
    
    missing_df = pd.DataFrame(grid_response["data"])

    if st.button('Execute Analysis'):   
        missing_df.to_excel(actual_missing_data_file,index=False)
        index =1

    return missing_df ,index

def process_sentiment_data(df): 
    st.sidebar.success('Sentiment Processing...')
    df = df.drop_duplicates()
    sen_df = sematic_classification.sematic_analysis(df)
    st.sidebar.success('Sentiment Done, see Sentiment Data Session')
    return sen_df 

def analysis_sentiment_data(df):
    select_columns = ['Component Name', 'CVE ID', 'Descriptions', 'Severity', 'Classification']
    df_selected = df[select_columns]
    st.dataframe(df_selected, height=600, use_container_width=True)

def append_dataframes(df1, df2):
    return pd.concat([df1, df2], ignore_index=True).drop_duplicates()

def save_data(df, file_path):
    df.to_excel(file_path)
    update_histogram_chart()

def update_histogram_chart():
    with metrics_placeholder.container():
        col1, col2, col3 = st.columns(3)
        col1.metric(label="Sentiment Components", value=len(st.session_state.cve_data), delta=0)
        col2.metric(label="Missing Components", value=len(st.session_state.missing_data), delta=0)
        col3.metric(label="NVD Severity Components", value=len(st.session_state.nvd_data), delta=0)
        style_metric_cards(background_color="#071021", border_left_color="#1f66bd")

def run_on_startup():
    # if os.path.exists(source_path):
    #     shutil.rmtree(source_path)
    #     os.mkdir(source_path)
    # else:
    #     os.mkdir(source_path)

    destination_folder = os.path.join('Results',f"Sentimant_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    os.mkdir(destination_folder)
    st.session_state.destination_folder = destination_folder
    shutil.copy('Data/Component_Data.xlsx', st.session_state.destination_folder)
    st.session_state.missing_component_data = os.path.join(st.session_state.destination_folder,"Component_Data.xlsx")
    st.session_state.repo_file = os.path.join(st.session_state.destination_folder, "Component_Data.xlsx")
    st.session_state.get_components_file = os.path.join(st.session_state.destination_folder,'Component_File.xlsx')
    st.session_state.nvd_with_no_severity_file = os.path.join(st.session_state.destination_folder,'NVD_with_No_Severity.xlsx')
    st.session_state.actual_missing_data_file =os.path.join(st.session_state.destination_folder, 'Actual_missing_Data.xlsx')
    



def save_and_update(data, filename):
    save_data(data, os.path.join(st.session_state.destination_folder, filename))
    update_histogram_chart()

def display_classification_charts(df):
    classification_counts = df['Classification'].value_counts()
    critical_count = classification_counts.get('Critical', 0)
    non_critical_count = classification_counts.get('Non-Critical', 0)

    # Bar Chart
    bar_chart = px.bar(
        x=['Critical', 'Non-Critical'],
        y=[critical_count, non_critical_count],
        labels={'x': 'Classification', 'y': 'Count'},
        title='Classification Counts',
        height=400,  # Adjust height
        width=600   # Adjust width
    )

    # Pie Chart
    pie_chart = px.pie(
        names=['Critical', 'Non-Critical'],
        values=[critical_count, non_critical_count],
        title='Classification Distribution',
        height=400,  # Adjust height
        width=600   # Adjust width
    )

    return bar_chart, pie_chart

def display_component_counts(df):
    component_counts = df['Component Name'].value_counts().reset_index()
    component_counts.columns = ['Component Name', 'Count']

    # Bar Chart with multiple colors
    bar_chart = px.bar(
        component_counts,
        x='Component Name',
        y='Count',
        color='Component Name',
        labels={'Component Name': 'Component Name', 'Count': 'Count'},
        title='Unique Component Counts',
        height=400,  # Adjust height
        width=600   # Adjust width
    )

    return bar_chart

def display_nvd_counts(df):
    nvd_counts = df['File Name'].value_counts().reset_index()
    nvd_counts.columns = ['File Name', 'Count']

    # Bar Chart with multiple colors
    bar_chart = px.bar(
        nvd_counts,
        x='File Name',
        y='Count',
        color='File Name',
        labels={'File Name': 'File Name', 'Count': 'Count'},
        title='NVD Severity Counts not in 3.0-3.1 version',
        height=400,  # Adjust height
        width=600   # Adjust width
    )

    return bar_chart

if 'has_run_on_startup' not in st.session_state:
    run_on_startup()
    st.session_state.has_run_on_startup = True

if "cve_data" not in st.session_state:
    st.session_state.cve_data = pd.DataFrame()
    st.session_state.missing_data = pd.DataFrame()
    st.session_state.sen_data =pd.DataFrame()
    st.session_state.component_data = None 
    st.session_state.nvd_data = pd.DataFrame()
    st.session_state.len_cve_data = 0
    st.session_state.len_nvd_data = 0
    st.session_state.len_missing_data = 0


update_histogram_chart()

if button_1:
    if 'has_run_on_startup' not in st.session_state:
        run_on_startup()
        st.session_state.has_run_on_startup = True

    if upload_file is not None:
        st.sidebar.success("Destination Path:{}".format(st.session_state.destination_folder))

        json_data = json_to_excel(upload_file)

 
        
        cve_data = CVE_Extraction(data=json_data, repo_file=st.session_state.repo_file, get_components_file=st.session_state.get_components_file, nvd_with_no_severity_file=st.session_state.nvd_with_no_severity_file, actual_missing_data_file=st.session_state.actual_missing_data_file, api_key=api_key)
        
        if os.path.exists(st.session_state.get_components_file):
            sen_data = process_sentiment_data(pd.read_excel(st.session_state.get_components_file))
            st.session_state.sen_data = sen_data
        
        if os.path.exists(st.session_state.actual_missing_data_file):
            missing_data = pd.read_excel(st.session_state.actual_missing_data_file)
        else:
            missing_data = pd.DataFrame()

        if os.path.exists(st.session_state.nvd_with_no_severity_file):
            nvd_data = pd.read_excel(st.session_state.nvd_with_no_severity_file)
        else:
            nvd_data = pd.DataFrame()
        
        st.session_state.cve_data = cve_data
        st.session_state.nvd_data = nvd_data
        st.session_state.sen_data = sen_data

        save_and_update(cve_data, 'Final_CVE_Data.xlsx')
        save_and_update(nvd_data, 'Final_NVD_Data.xlsx')
        save_and_update(sen_data, 'Final_SEN_Data.xlsx')
    else:
        st.error("Load the component.json file")

if os.path.exists(st.session_state.get_components_file) :
    st.write("Detail Analysis")

    if os.path.exists(st.session_state.actual_missing_data_file):  
        cve_data =pd.DataFrame()
        missing_data ,index = process_missing_data(st.session_state.actual_missing_data_file)
        st.session_state.missing_data = missing_data
        if index == 1:
            st.sidebar.success("Missing Data CVE Analysis in progress")
        
            cve_data = CVE_Extraction(data= missing_data ,repo_file=st.session_state.repo_file,get_components_file=st.session_state.get_components_file,nvd_with_no_severity_file=st.session_state.nvd_with_no_severity_file,actual_missing_data_file=st.session_state.actual_missing_data_file,api_key=api_key) 
            
            st.sidebar.success("CVE Analysis in done for missing data")
            
            if os.path.exists(st.session_state.nvd_with_no_severity_file):
                nvd_data = pd.read_excel(st.session_state.nvd_with_no_severity_file)
            else:
                nvd_data = pd.DataFrame()
            
            if os.path.exists(st.session_state.get_components_file):
                sen_data = process_sentiment_data(pd.read_excel(st.session_state.get_components_file))
            else:
                sen_data = pd.DataFrame()
        
            st.session_state.cve_data = append_dataframes(st.session_state.cve_data,cve_data)
            st.session_state.nvd_data = append_dataframes(st.session_state.nvd_data,nvd_data)    
            st.session_state.sen_data = append_dataframes(st.session_state.sen_data,sen_data)   
            
            save_and_update(cve_data, 'Final_CVE_Data.xlsx')
            save_and_update(nvd_data, 'Final_NVD_Data.xlsx')
            save_and_update(sen_data, 'Final_SEN_Data.xlsx')
    else:
        st.sidebar.warning("No missing data is created")
        if os.path.exists(st.session_state.get_components_file):
            show_data = st.session_state.sen_data[['Component Name','CVE ID','Descriptions','Severity','Classification']]
            
            st.success('Unique Components:{}'.format(len(st.session_state.sen_data['Component Name'].unique())))
            
            classification_counts = st.session_state.sen_data['Classification'].value_counts()
            critical_count = classification_counts.get('Critical', 0)
            non_critical_count = classification_counts.get('Non-Critical', 0)
            st.success(f'Classification - Critical: {critical_count}, Non-Critical: {non_critical_count}')
            
            # Display charts in two columns
            col1, col2 = st.columns(2)
            with col1:
                bar_chart, pie_chart = display_classification_charts(st.session_state.sen_data)
                st.plotly_chart(bar_chart)
            with col2:
                st.plotly_chart(pie_chart)
            
            # Display component counts chart
            col3, col4 = st.columns(2)
            with col3:
                component_bar_chart = display_component_counts(st.session_state.sen_data)
                st.plotly_chart(component_bar_chart)
            with col4:
                if len(st.session_state.nvd_data) > 0:
                    nvd_bar_chart = display_nvd_counts(st.session_state.nvd_data)
                    st.plotly_chart(nvd_bar_chart)

            st.dataframe(show_data)

            # Save charts to session state for PDF generation
            st.session_state.bar_chart = bar_chart
            st.session_state.pie_chart = pie_chart
            st.session_state.component_bar_chart = component_bar_chart
            if len(st.session_state.nvd_data) > 0:
                st.session_state.nvd_bar_chart = nvd_bar_chart

if button_2:
    cve_data_path = os.path.join(st.session_state.destination_folder, 'Final_CVE_Data.xlsx')
    if os.path.exists(cve_data_path):
        cve_data = pd.read_excel(cve_data_path)
        semantic_data = process_sentiment_data(cve_data)
        save_data(semantic_data, os.path.join(st.session_state.destination_folder, 'Final_SEN_Data.xlsx'))
        st.success("Semantic Data Analysis completed and saved.")
    else:
        st.error("Final_CVE_Data.xlsx not found.")

