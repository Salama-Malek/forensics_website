import asyncio
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import login as auth_login, logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import HttpResponse
from django.conf import settings
from analysis.forms import EvidenceForm, MalwareAnalysisForm
from .models import Evidence, LogFile
import pyshark
import splunklib.results as splunk_results
import splunklib.client as splunk_client

# **********************************
# Dashboard
@login_required
def dashboard(request):
    return render(request, 'analysis/dashboard.html')

# **********************************
# User Registration
def register(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            auth_login(request, user)  # Automatically log the user in after registration
            return redirect('dashboard')
    else:
        form = UserCreationForm()
    return render(request, 'registration/register.html', {'form': form})

# **********************************
# User Logout
@login_required
def logout_view(request):
    auth_logout(request)
    return redirect('login')

# **********************************
# Upload Evidence
@login_required
def upload_evidence(request):
    if request.method == 'POST':
        form = EvidenceForm(request.POST, request.FILES)
        if form.is_valid():
            evidence = form.save(commit=False)
            evidence.user = request.user  # Associate evidence with the logged-in user
            evidence.save()
            messages.success(request, 'Evidence uploaded successfully!')
            return redirect('evidence_list')
    else:
        form = EvidenceForm()
    return render(request, 'analysis/upload_evidence.html', {'form': form})

# **********************************
# Evidence List - Only show user's own files
@login_required
def evidence_list(request):
    evidence = Evidence.objects.filter(user=request.user)  # Filter by user
    return render(request, 'analysis/evidence_list.html', {'evidence': evidence})

# **********************************
# Analyze PCAP (Synchronous)
@login_required
def analyze_pcap(request, evidence_id):
    evidence = get_object_or_404(Evidence, id=evidence_id, user=request.user)

    # Path to the uploaded PCAP file
    pcap_file_path = evidence.file.path

    # Ensure there's a running event loop for pyshark
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    # Load the PCAP file using pyshark
    try:
        capture = pyshark.FileCapture(pcap_file_path)
    except Exception as e:
        return HttpResponse(f'Error processing PCAP file: {str(e)}', status=500)

    # Extract packet information (first 10 packets)
    packet_data = []
    for packet in capture:
        packet_info = {
            'number': packet.number,
            'protocol': packet.highest_layer,
            'src_ip': getattr(packet, 'ip', None).src if hasattr(packet, 'ip') else 'N/A',
            'dst_ip': getattr(packet, 'ip', None).dst if hasattr(packet, 'ip') else 'N/A',
            'length': packet.length,
            'info': getattr(packet, 'info', None) if hasattr(packet, 'info') else 'N/A'
        }
        packet_data.append(packet_info)
        if len(packet_data) >= 10:  # Limit to first 10 packets
            break

    context = {
        'evidence': evidence,
        'packet_data': packet_data
    }

    return render(request, 'analysis/analyze_pcap.html', context)

# Helper function to process packets synchronously
def get_packet_data(pcap_file_path):
    capture = pyshark.FileCapture(pcap_file_path)
    packet_data = []
    for packet in capture:
        packet_info = {
            'number': packet.number,
            'protocol': packet.highest_layer,
            'src_ip': getattr(packet, 'ip', None).src if hasattr(packet, 'ip') else 'N/A',
            'dst_ip': getattr(packet, 'ip', None).dst if hasattr(packet, 'ip') else 'N/A',
            'length': packet.length,
            'info': getattr(packet, 'info', None) if hasattr(packet, 'info') else 'N/A'
        }
        packet_data.append(packet_info)
        if len(packet_data) >= 10:  # Limit to first 10 packets
            break
    return packet_data

# **********************************
# Upload Log File
@login_required
def upload_log(request):
    if request.method == 'POST':
        log_file = request.FILES['log_file']
        log_instance = LogFile.objects.create(file=log_file, user=request.user)  # Associate log with user
        return redirect('analyze_log', log_id=log_instance.id)
    return render(request, 'analysis/upload_log.html')

# **********************************
# Analyze Log File (Splunk)
@login_required
def analyze_log(request, log_id):
    log = get_object_or_404(LogFile, id=log_id, user=request.user)

    try:
        service = splunk_client.connect(
            host=settings.SPLUNK_HOST,
            port=settings.SPLUNK_PORT,
            username=settings.SPLUNK_USERNAME,
            password=settings.SPLUNK_PASSWORD
        )
    except Exception as e:
        return HttpResponse(f'Error connecting to Splunk: {str(e)}', status=500)

    search_query = 'search index=main sourcetype=access_combined'
    job = service.jobs.create(search_query)

    while not job.is_done():
        pass

    results = splunk_results.ResultsReader(job.results())
    search_results = [result for result in results if isinstance(result, dict)]

    context = {
        'log': log,
        'search_results': search_results
    }
    return render(request, 'analysis/analyze_log.html', context)

# **********************************
# Malware Analysis
@login_required
def add_analysis(request):
    if request.method == 'POST':
        form = MalwareAnalysisForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Malware analysis submitted successfully!')
            return redirect('dashboard')
    else:
        form = MalwareAnalysisForm()

    return render(request, 'analysis/add_analysis.html', {'form': form})


# **********************************
# Download Report
@login_required
def download_report(request, evidence_id):
    evidence = get_object_or_404(Evidence, id=evidence_id, user=request.user)

    response = HttpResponse(content_type='text/plain')
    response['Content-Disposition'] = f'attachment; filename="evidence_{evidence_id}_report.txt"'

    response.write(f"Evidence ID: {evidence.id}\n")
    response.write(f"File Name: {evidence.file.name}\n")
    response.write(f"Uploaded on: {evidence.created_at}\n\n")

    analysis = evidence.malwareanalysis_set.all()
    if analysis.exists():
        for a in analysis:
            response.write(f"Analysis Result: {a.analysis_result}\n")
            response.write(f"Analyzed on: {a.created_at}\n\n")
    else:
        response.write("No analysis available for this evidence.\n")

    return response
