class FieldElement:
    """
    a single finite field element
    """

    def __init__(self, num, prime):
        if num >= prime or num < 0:  # check inappropriate value
            error = 'Num {} not in field range 0 to {}'.format(
                num, prime - 1)
            raise ValueError(error)
        self.num = num  # assign initial value
        self.prime = prime

    def __repr__(self):
        return 'FieldElement_{}({})'.format(self.prime, self.num)

    def __eq__(self, other):
        if other is None:  # assign initial value
            return False
        return self.num == other.num and self.prime == other.prime  # equality test

    def __ne__(self, other):
        # the inverse of the == operator
        return not self == other

    def __add__(self, other):
        if self.prime != other.prime:  # ensure elements from the same finite field
            raise TypeError('Cannot add two numbers in different Fields')
        num = (self.num + other.num) % self.prime  # modular addition
        return self.__class__(num, self.prime)  # new finite field element

    def __sub__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot subtract two numbers in different Fields')
        # self.num and other.num are the actual values
        # self.prime is what we need to mod against
        num = (self.num - other.num) % self.prime
        # return an element of the same class
        return self.__class__(num, self.prime)

    def __mul__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot multiply two numbers in different Fields')
        # self.num and other.num are the actual values
        # self.prime is what we need to mod against
        num = (self.num * other.num) % self.prime
        # return an element of the same class
        return self.__class__(num, self.prime)

    def __pow__(self, exponent):
        n = exponent % (self.prime - 1)  # n ~ [0, p-2]
        num = pow(self.num, n, self.prime)
        return self.__class__(num, self.prime)

    def __truediv__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot divide two numbers in different Fields')
        # use fermat's little theorem:
        # self.num**(p-1) % p == 1
        # this means:
        # 1/n == pow(n, p-2, p)
        num = self.num * pow(other.num, self.prime - 2, self.prime) % self.prime
        # return an element of the same class
        return self.__class__(num, self.prime)
    
    def __rmul__(self, coefficient):
        num = (self.num * coefficient) % self.prime
        return self.__class__(num, self.prime)