from log_events import logger
from dashboard import create_visualizations
from packet_processor import PacketProcessor, start_packet_capture
import streamlit as st
import time
from scapy.all import get_if_list


def main():
    st.set_page_config(
        page_title="Network Traffic Dashboard",
        layout="wide",
    )
    st.title("Network Traffic Dashboard")

    # Check if running as root
    import os
    if os.geteuid() != 0:
        st.error("⚠️ Not running as root! Packet capture requires root privileges. Run with: sudo -E streamlit run app.py")
        st.stop()

    # Initialize Packet Processor
    if 'processor' not in st.session_state:
        try:
            st.session_state.processor = start_packet_capture()
            st.session_state.start_time = time.time()
            st.success("✅ Packet capture started successfully!")
        except Exception as e:
            st.error(f"Failed to start packet capture: {e}")
            logger.error(f"Failed to start packet capture: {e}")
            st.stop()

    
    # Create dashboard layout
    col1, col2, col3 = st.columns(3)

    # Get current data
    df = st.session_state.processor.get_dataframe()


    # Display metrics
    with col1:
        st.metric("Total Packets", len(df))
    with col2:
        duration = time.time() - st.session_state.start_time
        st.metric("Capture Duration", f"{duration:.2f}s")
    with col3:
        # Show available interfaces
        interfaces = get_if_list()
        st.metric("Interfaces Available", len(interfaces))

    # Display visualizations
    create_visualizations(df)

    # Display recent packets
    st.subheader("Recent Packets")
    if len(df) > 0:
        st.dataframe(
            df.tail(10)[['timestamp', 'source', 'destination', 'protocol', 'size']],
            use_container_width=True
        )


    # Add refresh button
    if st.button("Refresh Data"):
        st.rerun()

    # Auto refresh
    time.sleep(5)
    st.rerun()


if __name__ == "__main__":
    main()