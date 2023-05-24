// declare R to be public
pub R;

// define the Pythagorean relation we are checking
def pyth a b c = {
  a^2 + b^2 = c^2
};

// appends constraint x^2 + y^2 = R^2 to the circuit
pyth x y R;