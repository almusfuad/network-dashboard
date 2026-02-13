import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from scapy.all import *
from collections import defaultdict
import time
from datetime import datetime
import warnings
from typing import List, Dict, Optional
import socket


# create visualizations
def create_visualizations(df: pd.DataFrame):
    """Create all dashboard visualizations."""
    if len(df) > 0:
        # Protocol Distribution
        protocols_count = df['protocol'].value_counts()
        fig_protocol = px.pie(
            values=protocols_count.values, 
            names=protocols_count.index, 
            title='Protocol Distribution'
        )
        st.plotly_chart(fig_protocol, use_container_width=True)


        # Packets timeline
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df_grouped = df.groupby(
            df['timestamp'].dt.floor('T')
        ).size()
        fig_timeline = px.line(
            x=df_grouped.index, 
            y=df_grouped.values,   
            title='Packets Over Time',
        )
        st.plotly_chart(fig_timeline, use_container_width=True)


        # Top Source IPs
        top_sources = df['source'].value_counts().head(10)
        fig_top_sources = px.bar(
            x=top_sources.index, 
            y=top_sources.values, 
            title='Top Source IP addresses',
        )
        st.plotly_chart(fig_top_sources, use_container_width=True)
