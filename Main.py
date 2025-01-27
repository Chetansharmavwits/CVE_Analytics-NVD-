import streamlit as st
import pandas as pd
import pandas as pd 
import pandas as pd
from transformers import pipeline
from Utils.data_extraction import CVE_Extraction ,json_to_excel
from Utils import sematic_classification 
from streamlit_extras.metric_cards import style_metric_cards
from st_aggrid import AgGrid,GridOptionsBuilder,GridUpdateMode
from datetime import datetime
import shutil 
import os 
from streamlit_extras.app_logo import add_logo
from dotenv import load_dotenv

load_dotenv()

keywords_file = os.getenv("keywords_file")
missing_component_data = os.getenv("missing_component_data")
repo_file = os.getenv("repo_file")
get_components_file = os.getenv("get_components_file")
nvd_with_no_severity_file = os.getenv("nvd_with_no_severity_file")
actual_missing_data_file = os.getenv("actual_missing_data_file")
api_key = os.getenv("api_key")
source_path = os.getenv("source_path")
destination_path = os.getenv("destination_path")
cve_file_path = os.getenv("cve_file_path")
nvd_file_path = os.getenv("nvd_file_path")
sen_file_path = os.getenv("sen_file_path")


st.set_page_config(page_title="Analytics Dashboard", page_icon="🌎", layout="wide")  
st.title("📈 CVE Analytics Dashboard ")

with open('style.css')as f:
    st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html = True)

st.logo("Icon/CVE_Icon.png",size= "large")
st.sidebar.header("CVE Analysis Parameter")
upload_file = st.sidebar.file_uploader("Upload a Json Config File",type = "json")
placeholder = st.empty()

def display_keywords(keyword_dict):
   df =pd.DataFrame({"Type":list(keyword_dict.keys()), "Keywords":[",".join(words) for words in keyword_dict.values()]})
   st.dataframe(df,use_container_width = True,hide_index=True)

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

    if st.button('Save Data'):   
        missing_df.to_excel(actual_missing_data_file,index=False)
        index =1

    return missing_df ,index

def process_sentiment_data(df): 
    st.sidebar.success('Sentimant Procressing...')
    df = df.drop_duplicates()

    sen_df  = sematic_classification.sematic_analysis(df)
    st.sidebar.success('Sentimant Done, see Sentimant Data Session')
    print("Sentimant Done")
    return sen_df 

def analysis_sentiment_data(df):
    select_collumns = ['Component Name',
                       'CVE ID',
                       'Descriptions',
                       'Severity',
                       'Classification',
]
    df_selected = df[select_collumns]
    st.dataframe(df_selected,height= 600,use_container_width= True)

def append_dataframes(df1,df2):
    return pd.concat([df1,df2],ignore_index=True).drop_duplicates()

def save_data(df,file_path):
    df.to_excel(file_path)

def update_histogram_chart():
    col1, col2, col3 = st.columns(3)
    with placeholder.container():
        col1.metric(label="Sentiment Components", value=st.session_state.len_cve_data, delta=0)
        col2.metric(label="Missing Components", value=st.session_state.len_missing_data, delta=0)
        col3.metric(label="NVD Serverity Componets", value=st.session_state.len_nvd_data, delta=0)

        style_metric_cards(background_color="#071021",border_left_color="#1f66bd")

def run_on_startup():
    if os.path.exists(source_path):
        shutil.rmtree(source_path)
        os.mkdir(source_path)
    else:
        os.mkdir(source_path)
    destination_folder = os.path.join('Results',f"Sentimant_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    os.mkdir(destination_folder)
    st.session_state.destination_folder = destination_folder
    

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

if st.sidebar.button("Analysis the Component Json "):
        if 'has_run_on_startup' not in st.session_state:
            run_on_startup()
            st.session_state.has_run_on_startup = True

        if upload_file is not None:

            json_data = json_to_excel(upload_file)
            
            with st.spinner("CVE Data in progress, Loading..   Please wait..."): 
                cve_data = CVE_Extraction(data =json_data,repo_file=repo_file,get_components_file=get_components_file,nvd_with_no_severity_file=nvd_with_no_severity_file,actual_missing_data_file=actual_missing_data_file,api_key=api_key)             
            
            if os.path.exists(get_components_file):
                sen_data = process_sentiment_data(pd.read_excel(get_components_file))
                st.session_state.sen_data = sen_data
            
            if os.path.exists(actual_missing_data_file ):
                missing_data = pd.read_excel(actual_missing_data_file)
            else:
                missing_data =pd.DataFrame()

            if os.path.exists(nvd_with_no_severity_file):
                nvd_data = pd.read_excel(nvd_with_no_severity_file)
            else:
                nvd_data = pd.DataFrame()
            
            st.session_state.cve_data = cve_data
            st.session_state.nvd_data = nvd_data
        else:
            st.error("Load the component.json file")
    
if os.path.exists(get_components_file) :
    st.write("Detail Analysis")
    if os.path.exists(actual_missing_data_file):  
        cve_data =pd.DataFrame()
        missing_data ,index = process_missing_data(actual_missing_data_file)
        st.session_state.missing_data = missing_data
        

        if index == 1:
            st.sidebar.success("Missing Data CVE Analysis in progress")
            with st.spinner("CVE for Missing Data,Loading....   Please wait..."): 
                cve_data = CVE_Extraction(data= missing_data ,repo_file=repo_file,get_components_file=get_components_file,nvd_with_no_severity_file=nvd_with_no_severity_file,actual_missing_data_file=actual_missing_data_file,api_key=api_key) 
            
            st.sidebar.success("CVE Analysis in done for missing data")
            
            if os.path.exists(nvd_with_no_severity_file):
                nvd_data = pd.read_excel(nvd_with_no_severity_file)
            else:
                nvd_data = pd.DataFrame()
            
            if os.path.exists(get_components_file):
                sen_data = process_sentiment_data(pd.read_excel(get_components_file))
            else:
                sen_data = pd.DataFrame()
            
            st.session_state.cve_data = append_dataframes(st.session_state.cve_data,cve_data)
            st.session_state.nvd_data = append_dataframes(st.session_state.nvd_data,nvd_data)    
            st.session_state.sen_data = append_dataframes(st.session_state.sen_data,sen_data)
    else: 
         st.sidebar.warning("No missing data is created")
         if os.path.exists(get_components_file):
             st.dataframe(st.session_state.cve_data)
         

if os.path.exists(get_components_file) : 
    st.session_state.len_cve_data = len(st.session_state.cve_data)
    st.session_state.len_missing_data = len(st.session_state.missing_data)
    st.session_state.len_nvd_data = len(st.session_state.nvd_data)
    save_data(st.session_state.cve_data,os.path.join(st.session_state.destination_folder,'Final_CVE_Data.xlsx'))
    save_data(st.session_state.nvd_data,os.path.join(st.session_state.destination_folder,'Final_NVD_Data.xlsx'))
    save_data(st.session_state.sen_data,os.path.join(st.session_state.destination_folder,'Final_SEN_Data.xlsx'))
    



