# Network-Diagnostic-and-Tool-Package
Overview

	This project is a Network Toolkit GUI built with Python, 
	designed to provide various network diagnostic and communication functionalities through an intuitive graphical user interface (GUI). 
	It leverages Python's socket library for network operations, tkinter for the GUI, 
	and other supporting libraries for additional features like logging, threading, and JSON configuration management.

The toolkit supports multiple network-related tasks such as:

	Retrieving machine information (hostname, IP address).

	Echo testing (server and client modes).

	SNTP time synchronization.

	Simple chat functionality (server and client modes).

	Socket buffer size modification and timeout testing.

	Theme switching (dark/light mode).

Features

	Machine Information Module: Displays local hostname, IP address, and demonstrates IP packing/unpacking.,
	
	Echo Test Module: Implements TCP-based echo server and client for testing network communication.
	
	SNTP Time Synchronization Module: Fetches time from an NTP server.
	
	Simple Chat Module: Provides a basic chat system over TCP with server and client modes.
	
	Socket Configuration: Allows adjustment of send/receive buffer sizes, blocking/non-blocking modes, and socket timeouts.
	
	GUI Features: Dark/light theme toggle, real-time output display, chat input, and progress bar.
	
	Settings Persistence: Saves and loads settings (buffer sizes, timeout, etc.) to/from a JSON file.
	
	Logging: Logs activities and errors to a file (network_toolkit.log) and chat history to chat_history.txt.	

Requirements

	Python 3.x
	Required libraries (install via pip):
	tkinter (usually comes with Python)
	No additional external libraries are required beyond the Python standard library.
	
Notes

	The application uses a single port for both server and client operations in most modules. 
	Ensure the port is free before starting a server.
	
	The chat module supports only one client connection at a time.
	
	Errors and exceptions are logged to network_toolkit.log and displayed in the GUI.
	
	The application is multi-threaded using ThreadPoolExecutor to handle tasks without freezing the GUI.	
