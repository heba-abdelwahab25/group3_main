"""
Example usage of the flexible client
Demonstrates different ways to use the client programmatically
"""
from flexible_client import client_node, simulate_load, PQCKyber, RSAEngine, PQC_AVAILABLE, RSA_AVAILABLE

def example_single_client():
    """Example: Run a single client"""
    print("=" * 60)
    print("Example 1: Single PQC Client")
    print("=" * 60)
    if PQC_AVAILABLE:
        client_node(1, "PQCKyber")
    else:
        print("PQC library not available")

def example_single_rsa():
    """Example: Run a single RSA client"""
    print("\n" + "=" * 60)
    print("Example 2: Single RSA Client")
    print("=" * 60)
    if RSA_AVAILABLE:
        client_node(1, "RSA")
    else:
        print("RSA library not available")

def example_load_test():
    """Example: Load test with multiple clients"""
    print("\n" + "=" * 60)
    print("Example 3: Load Test (10 clients)")
    print("=" * 60)
    simulate_load(num_nodes=10, crypto_choice="PQCKyber")

def example_mixed_crypto():
    """Example: Mixed crypto load test"""
    print("\n" + "=" * 60)
    print("Example 4: Mixed Crypto Load Test")
    print("=" * 60)
    simulate_load(num_nodes=6, crypto_choice="mixed")

def example_staggered():
    """Example: Staggered connections"""
    print("\n" + "=" * 60)
    print("Example 5: Staggered Connections")
    print("=" * 60)
    simulate_load(num_nodes=5, crypto_choice="PQCKyber", stagger=True, stagger_delay=0.2)

if __name__ == "__main__":
    # Run examples
    # Uncomment the examples you want to run:
    
    # example_single_client()
    # example_single_rsa()
    # example_load_test()
    # example_mixed_crypto()
    # example_staggered()
    
    print("Uncomment examples in the script to run them")
    print("\nOr use the command line interface:")
    print("  python flexible_client.py --nodes 5 --crypto PQCKyber")
    print("  python flexible_client.py --single --crypto RSA")

